#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-109618 批量评估控制台（本地 Web GUI，零第三方依赖）

用法:
    python3 gui/server.py --host 127.0.0.1 --port 8899
    浏览器打开 http://127.0.0.1:8899

设计要点:
- 本工具**只做 CVE-2026-109618**：不含 SQLi/XSS/CSRF/LFI/命令注入等任何通用 Web 扫描；
- 引擎只有 attack/p2s_ext.py，每个目标一个子进程（崩溃/超时隔离），可配并发；
- 两种模式：
    recon     四前置分级（版本/消费点/post_max>memory_limit/堆可标定），默认只读；
              勾选「深度探测」才发 OOM 落点探测（最大 16MB body，可能 5xx）；
    oneclick  真实 RCE 链（需再勾选「确认执行攻击」）：Stage-1/2 泄漏 + 伪造 HashTable +
              短命令执行 + HTTP 回读 proof，结果取 oneclick_report.json；
- 公网目标必须勾选「已获授权」且（推荐）填授权范围，否则服务端直接 denied（不发起任何请求）；
- 所有结果落盘到 gui_runs/<job_id>/，支持 JSON / CSV 导出。
"""
import argparse
import csv
import io
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
P2S = os.path.join(ROOT, "attack", "p2s_ext.py")
PY = sys.executable or "python3"

def _max_workers():
    """GUI 并发上限：环境变量 P2S_MAX_WORKERS（默认 16，硬上限 64）。"""
    try:
        n = int(os.environ.get("P2S_MAX_WORKERS", "16") or 16)
    except ValueError:
        n = 16
    return max(1, min(64, n))
STATIC = os.path.join(HERE, "static")
WORKROOT = os.environ.get("WS_GUI_WORK") or os.path.join(os.getcwd(), "gui_runs")

JOBS = {}
JOBS_LOCK = threading.Lock()
SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def load_snapshot(jid):
    """服务重启后仍可查看历史任务：从 gui_runs/<job_id>/report.json 读取"""
    if not re.match(r"^[\w.-]+$", jid or ""):
        return None
    p = os.path.join(WORKROOT, jid, "report.json")
    if not os.path.isfile(p):
        return None
    try:
        with io.open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None



# ------------------------------------------------------------------ 工具函数
def _host_of(target):
    """从 URL / host:port / [v6]:port 中取出纯主机名或 IP"""
    t = (target or "").strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in t:
        t = t.rsplit("@", 1)[1]
    if t.startswith("["):
        return t[1:].split("]", 1)[0]
    if t.count(":") == 1:
        h, _, port = t.partition(":")
        if port.isdigit():
            return h
    return t


def is_public_host(host):
    """公网判定：非回环/私网/链路本地/link-local 视为公网"""
    if not host:
        return False
    h = _host_of(host).strip("[]").lower()
    if h in ("localhost", "localhost.localdomain"):
        return False
    try:
        ips = [h] if re.match(r"^[\d.]+$", h) or ":" in h else []
        if not ips:
            ips = [socket.gethostbyname(h)]
    except Exception:
        # 解析失败按公网处理（更保守）
        return True
    for ip in ips:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return True
        if not a.is_global:  # 回环/私网/链路本地/保留/文档段(TEST-NET) 一律视为非公网
            return False
    return True


def all_targets_private(targets):
    """全部目标都是内网/回环 → 视为本地靶场，无需公网授权声明"""
    if not targets:
        return False
    return all(not is_public_host(t) for t in targets)


def scope_match(host, entries):
    """scope 条目：精确域名 / *.domain（含裸域）/ CIDR / URL 前缀"""
    if not entries:
        return False
    h = (host or "").strip("[]").lower()
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        ip = None
    for e in entries:
        e = e.strip()
        if not e or e.startswith("#"):
            continue
        if "://" in e:
            eh = (urlparse(e).hostname or "").lower()
            if eh and (h == eh or h.endswith("." + eh)):
                return True
            continue
        if e.startswith("*."):
            base = e[2:].lower()
            if h == base or h.endswith("." + base):
                return True
            continue
        if "/" in e:
            try:
                net = ipaddress.ip_network(e, strict=False)
            except ValueError:
                continue
            if ip is not None and ip in net:
                return True
            if ip is None:
                try:
                    if ipaddress.ip_address(socket.gethostbyname(h)) in net:
                        return True
                except Exception:
                    pass
            continue
        if h == e.lower() or h.endswith("." + e.lower()):
            return True
    return False


def normalize_target(raw):
    t = (raw or "").strip()
    if not t or t.startswith("#"):
        return None
    if "://" not in t:
        t = "http://" + t
    return t


def derive_scope(targets):
    """粘贴即范围：把本次粘贴的目标主机固化为审计用的 scope。

    目标本身就是测试边界，因此无需再手填「授权范围」；仍保留 authorized 声明，
    用于区分「自有/已授权资产」与「未授权公网」。
    """
    out, seen = [], set()
    for raw in targets:
        t = normalize_target(raw)
        if not t:
            continue
        h = urlparse(t).hostname
        if h and h.lower() not in seen:
            seen.add(h.lower())
            out.append(h)
    return out


def cve_verdict(rc, mode):
    """把 CLI 退出码映射成 CVE-2026-109618 专用结论。"""
    if mode == "oneclick":
        return {0: "RCE_CONFIRMED", 10: "RCE_LIKELY", 20: "DOS_ONLY", 30: "NOT_AFFECTED",
                40: "NO_SINK", 50: "UNREACHABLE", 3: "DENIED"}.get(rc, "UNKNOWN")
    return {0: "AFFECTED", 10: "RCE_LIKELY", 15: "UNKNOWN_VERSION", 20: "DOS_ONLY",
            30: "NOT_AFFECTED", 40: "NO_SINK", 50: "UNREACHABLE", 3: "DENIED"}.get(rc, "UNKNOWN")


def cve_status(rc):
    return {0: "found", 10: "likely", 20: "dos", 15: "unknown", 30: "clean",
            40: "clean", 3: "denied", 50: "error"}.get(rc, "error")


def cve_severity(rc):
    return {0: "critical", 10: "high", 20: "low"}.get(rc, "info")


def synth_cve(log, rc, url, mode, report, err):
    """把 recon/oneclick 的 JSON 报告或退出码转成 GUI 目标记录。"""
    report = report if isinstance(report, dict) else {}
    verdict = report.get("verdict") or cve_verdict(rc, mode)
    ver = report.get("php_version") or report.get("version") or ""
    if isinstance(ver, dict):
        ver = ver.get("version") or ""
    sink = report.get("sink") or (report.get("sinks") or [None])[0] or ""
    pre = report.get("precondition") or {}
    ev = {
        "mode": mode, "verdict": verdict, "version": str(ver or ""),
        "sink": str(sink or ""),
        "profile": report.get("profile") or report.get("profile_source") or "",
        "rce": bool(report.get("rce")),
        "proof_body": (report.get("proof_body") or "")[:400],
        "proof_url": report.get("proof_url") or "",
        "postex_rc": report.get("postex_rc"),
        "steps": report.get("steps") or [],
        "report_error": err,
    }
    if isinstance(pre, dict):
        ev["post_max_gt_memory"] = pre.get("post_max_gt_memory_limit", pre.get("post_max_size_gt_memory_limit"))
        ev["oom_at_mb"] = pre.get("oom_at_mb")
        ev["post_max_hit_mb"] = pre.get("post_max_hit_mb")
    elif isinstance(report.get("deep"), dict):
        d = report["deep"]
        ev["post_max_gt_memory"] = d.get("post_max_gt_memory_limit", d.get("post_max_size_gt_memory_limit"))
        ev["oom_at_mb"] = d.get("oom_at_mb")
        ev["post_max_hit_mb"] = d.get("post_max_hit_mb")
    desc = "[%s] %s → %s (exit %s)" % (mode, url, verdict, rc)
    if ev["version"]:
        desc += "；PHP %s" % ev["version"]
    if ev.get("oom_at_mb") is not None:
        desc += "；OOM@%sMB" % ev["oom_at_mb"]
    if ev.get("post_max_gt_memory"):
        desc += "；post_max>memory_limit"
    if ev["proof_body"]:
        desc += "；proof=%s" % ev["proof_body"].replace("\n", " ")[:120]
    finding = {
        "type": "cve-2026-109618",
        "title": "CVE-2026-109618 %s" % verdict,
        "severity": cve_severity(rc),
        "url": url,
        "mode": mode,
        "verdict": verdict,
        "version": ev["version"],
        "detail": desc,
    }
    tgt = {"status": cve_status(rc), "rc": rc, "summary": desc,
           "findings": [finding] if rc in (0, 10) else [],
           "evidence": ev, "verdict": verdict, "log": log[-20000:]}
    return tgt


def safe_name(url, i):
    h = urlparse(url).hostname or "host"
    p = urlparse(url).port
    base = re.sub(r"[^A-Za-z0-9_.-]", "_", "%s%s" % (h, ("_%s" % p) if p else ""))
    return "%02d_%s" % (i, base[:60])


# ------------------------------------------------------------------ Job
class Job(object):
    def __init__(self, targets, opts, authorized, scope):
        self.id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
        self.dir = os.path.join(WORKROOT, self.id)
        os.makedirs(self.dir, exist_ok=True)
        self.created = time.time()
        self.opts = opts
        self.authorized = bool(authorized)
        self.scope = scope
        self.scope_file = None
        if scope:
            self.scope_file = os.path.join(self.dir, "scope.txt")
            with io.open(self.scope_file, "w", encoding="utf-8") as f:
                f.write("\n".join(scope) + "\n")
        self.stop_flag = threading.Event()
        self.lock = threading.Lock()
        self.done = 0
        self.total = 0
        self.status = "running"
        self.targets = []
        for i, raw in enumerate(targets):
            self.targets.append({
                "idx": i, "raw": raw, "url": raw, "host": "",
                "public": False, "status": "queued", "rc": None,
                "started": None, "ended": None, "duration": None,
                "findings": [], "summary": {}, "error": "", "log": "",
                "fingerprint": None, "out": None,
            })
        self.total = len(self.targets)
        self._t0 = time.time()

    # ---- 单目标执行
    def _run_one(self, tgt):
        if self.stop_flag.is_set():
            with self.lock:
                tgt["status"] = "stopped"
            return
        raw = tgt["raw"]
        url = normalize_target(raw)
        if not url:
            with self.lock:
                tgt["status"] = "skipped"
                tgt["error"] = "空行/注释"
            return
        host = (urlparse(url).hostname or "").lower()
        pub = is_public_host(host)
        with self.lock:
            tgt["url"], tgt["host"], tgt["public"] = url, host, pub
            tgt["started"] = time.time()
            tgt["status"] = "running"
        # 授权闸门：公网目标必须已授权，且（若填了 scope）必须命中
        if pub and not self.authorized:
            with self.lock:
                tgt["status"] = "denied"
                tgt["rc"] = 3
                tgt["error"] = "公网目标未确认授权，未发起任何请求"
                tgt["ended"] = time.time()
                tgt["duration"] = 0.0
            return
        if self.scope and not scope_match(host, self.scope):
            with self.lock:
                tgt["status"] = "denied"
                tgt["rc"] = 3
                tgt["error"] = "不在授权范围（scope）内，未发起任何请求"
                tgt["ended"] = time.time()
                tgt["duration"] = 0.0
            return

        o = self.opts
        mode = (o.get("mode") or "recon").lower()
        if mode not in ("recon", "oneclick"):
            mode = "recon"
        name = safe_name(url, tgt["idx"])
        log_path = os.path.join(self.dir, name + ".log")
        args = ["-u", url]
        if o.get("insecure"):
            args.append("--insecure")
        if o.get("timeout"):
            args += ["--timeout", str(o["timeout"])]
        if getattr(self, "authorized", False):
            args.append("--i-have-authorization")
        py = [PY, str(P2S)]
        if mode == "recon":
            report_path = os.path.join(self.dir, name + ".recon.json")
            cmd = py + ["recon"] + args + ["--json"]
            if o.get("deep"):
                cmd += ["--deep", "--budget", str(o.get("budget") or 6),
                        "--delay", str(o.get("delay") if o.get("delay") is not None else 0.3)]
                if o.get("probe_sizes"):
                    cmd += ["--probe-sizes", str(o["probe_sizes"])]
        else:
            outdir = os.path.join(self.dir, "oc_" + name)
            report_path = os.path.join(outdir, "oneclick_report.json")
            cmd = py + ["oneclick"] + args + [
                "--http-read", url,
                "--rounds", str(o.get("rounds") or 6),
                "--tries", str(o.get("tries") or 2),
                "--force", "--postex",
                "--only", str(o.get("only") or "id"),
                "--outdir", outdir,
            ]
        _pt = int(o.get("per_target_timeout") or 900)
        rc, log = self._exec(cmd, log_path, _pt)
        report, perr = self._load_report(report_path, log)
        return synth_cve(log, rc, url, mode, report, perr)

    def _load_report(self, path, log):
        """优先读报告文件；失败则从 stdout 抽取最后一个 JSON 对象。"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f), ""
        except Exception as e:
            err = "%s: %s" % (type(e).__name__, e)
        i, j = log.find("{"), log.rfind("}")
        if 0 <= i < j:
            try:
                return json.loads(log[i:j + 1]), ""
            except Exception as e2:
                err += " / stdout JSON 解析失败: %s" % e2
        return None, err

    def _exec(self, cmd, log_path, timeout):
        try:
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               timeout=timeout, cwd=ROOT)
            out = (p.stdout or b"").decode("utf-8", "replace")
            rc = p.returncode
        except subprocess.TimeoutExpired as e:
            out = ((e.stdout or b"").decode("utf-8", "replace")
                   + "\n[TIMEOUT] 超过 %ss，已终止" % timeout)
            rc = 2
        except Exception as e:
            out, rc = "[EXEC ERROR] %s" % e, 2
        with io.open(log_path, "a", encoding="utf-8") as f:
            f.write(out)
        return rc, out

    def run(self):
        # 并发上限可配：P2S_MAX_WORKERS（默认 16，硬上限 64），避免硬编码 8 拖慢大批量
        workers = max(1, min(_max_workers(), int(self.opts.get("concurrency", 8))))
        print("[job] workers=%d targets=%d mode=%s" % (workers, len(self.targets), self.opts.get("mode")), flush=True)
        try:
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futs = {ex.submit(self._run_one, t): i for i, t in enumerate(self.targets)}
                for fut in as_completed(futs):
                    i = futs[fut]
                    try:
                        res = fut.result()
                    except Exception as e:
                        with self.lock:
                            self.targets[i]["status"] = "error"
                            self.targets[i]["error"] = "%s: %s" % (type(e).__name__, e)
                        continue
                    if isinstance(res, dict):
                        with self.lock:
                            self.targets[i].update(res)
        finally:
            self.status = "stopped" if self.stop_flag.is_set() else "done"
            with io.open(os.path.join(self.dir, "report.json"), "w", encoding="utf-8") as f:
                json.dump(self.snapshot(), f, ensure_ascii=False, indent=1)

    def stop(self):
        self.stop_flag.set()

    # ---- 快照
    def snapshot(self, with_log=True):
        sev = {k: 0 for k in SEV_ORDER}
        types = {}
        for t in self.targets:
            for f in t["findings"]:
                s = (f.get("severity") or "info").lower()
                sev[s] = sev.get(s, 0) + 1
                types[f.get("type", "?")] = types.get(f.get("type", "?"), 0) + 1
        tg = []
        for t in self.targets:
            d = dict(t)
            if not with_log:
                d.pop("log", None)
            else:
                d["log"] = t.get("log", "")[-1500:]
            d["counts"] = {k: sum(1 for f in t["findings"]
                                  if (f.get("severity") or "info").lower() == k) for k in SEV_ORDER}
            tg.append(d)
        return {
            "job_id": self.id, "status": self.status,
            "created": self.created, "elapsed": round(time.time() - self._t0, 1),
            "authorized": self.authorized, "scope": self.scope,
            "opts": {k: v for k, v in self.opts.items()},
            "total": self.total,
            "done": sum(1 for t in self.targets
                        if t["status"] in ("found", "clean", "error", "denied", "skipped", "stopped")),
            "severity": sev, "types": types, "targets": tg,
        }


# ------------------------------------------------------------------ HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "WS-GUI/1.0"

    def log_message(self, fmt, *args):
        pass

    # ---- helpers
    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _static(self, rel):
        path = os.path.normpath(os.path.join(STATIC, rel))
        if not path.startswith(STATIC) or not os.path.isfile(path):
            return self._send(404, {"error": "not found"})
        ctype = {"html": "text/html; charset=utf-8", "js": "application/javascript; charset=utf-8",
                 "css": "text/css; charset=utf-8", "svg": "image/svg+xml"}.get(
            path.rsplit(".", 1)[-1], "application/octet-stream")
        with open(path, "rb") as f:
            self._send(200, f.read(), ctype)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except Exception:
            return {}

    # ---- routes
    def do_GET(self):
        p = urlparse(self.path).path
        if p in ("/", "/index.html"):
            return self._static("index.html")
        if p.startswith("/static/"):
            return self._static(p[len("/static/"):])
        if p == "/api/jobs":
            items = []
            try:
                names = [d for d in os.listdir(WORKROOT)
                         if os.path.isfile(os.path.join(WORKROOT, d, "report.json"))]
            except Exception:
                names = []
            names.sort(key=lambda d: os.path.getmtime(os.path.join(WORKROOT, d, "report.json")), reverse=True)
            for jid in names[:20]:
                snap = load_snapshot(jid) or {}
                items.append({"job_id": jid, "status": snap.get("status"),
                              "total": snap.get("total"), "created": snap.get("created")})
            return self._send(200, {"jobs": items, "workroot": WORKROOT})
        if p == "/api/health":
            return self._send(200, {"ok": True, "jobs": len(JOBS)})
        m = re.match(r"^/api/job/([^/]+)(?:/([\w.]+))?$", p)
        if m:
            jid, act = m.group(1), m.group(2)
            job = JOBS.get(jid)
            snap = job.snapshot() if job else load_snapshot(jid)
            if not snap:
                return self._send(404, {"error": "job not found"})
            if act in ("export.json", "export.csv", "export"):
                return self._export(snap, jid, act)
            return self._send(200, snap)
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        p = urlparse(self.path).path
        if p == "/api/scan":
            return self._start()
        if p == "/api/import/shodan":
            return self._shodan_import()
        m = re.match(r"^/api/job/([^/]+)/stop$", p)
        if m:
            job = JOBS.get(m.group(1))
            if not job:
                return self._send(404, {"error": "job not found"})
            job.stop()
            return self._send(200, {"ok": True, "job_id": job.id})
        return self._send(404, {"error": "not found"})

    _SELF_SCOPE_RE = re.compile(r"\b(?:net|org|hostname|asn):", re.I)

    def _shodan_import(self):
        """从 Shodan 导入「自有资产」候选目标。

        强制要求检索语句带 net:/org:/hostname:/asn: 限定，避免把公开引擎
        变成「全网挑选第三方受害者」的批量攻击入口；导入结果只是候选清单，
        仍需人工确认授权后才会进入扫描队列。
        """
        b = self._body()
        key = (b.get("api_key") or os.environ.get("SHODAN_API_KEY") or "").strip()
        q = (b.get("query") or "").strip()
        stats_only = bool(b.get("stats_only"))
        try:
            limit = int(b.get("limit") or 50)
        except Exception:
            limit = 50
        limit = max(1, min(200, limit))
        if not q:
            return self._send(400, {"error": 'query 必填，例如 net:203.0.113.0/24 或 org:"你的公司名"'})
        # 导入目标清单必须限定自有资产；stats_only 只回聚合计数，不产生任何 IP，因此放行任意 query
        if not stats_only and not self._SELF_SCOPE_RE.search(q):
            return self._send(400, {
                "error": 'Shodan 检索必须限定自有资产：请包含 net:/org:/hostname:/asn: 过滤条件。'
                         '本工具不提供“全网自动挑选可 RCE 第三方主机”的能力。'
                         '若只想了解某类指纹的分布，可勾选“仅统计（不返回 IP）”。',
                "query": q})
        if not key:
            return self._send(400, {"error": "缺少 Shodan API Key（也可 export SHODAN_API_KEY=...）"})
        if b.get("dry_run"):
            return self._send(200, {"dry_run": True, "query": q,
                                    "limit": limit, "stats_only": stats_only})
        try:
            import sys as _sys
            ad = os.path.join(ROOT, "attack")
            if ad not in _sys.path:
                _sys.path.insert(0, ad)
            from discover import shodan_search, shodan_count
            if stats_only:
                stats, err = shodan_count(key, q, timeout=25)
            else:
                pages = max(1, min(5, (limit + 99) // 100))
                matches, err = shodan_search(key, q, pages=pages, timeout=25)
        except Exception as e:
            return self._send(502, {"error": "Shodan 查询异常: %s" % e})
        if err:
            return self._send(502, {"error": "Shodan 查询失败: %s" % err})
        if stats_only:
            # 只返回聚合计数，绝不返回主机地址
            return self._send(200, {"query": q, "stats_only": True,
                                    "total": (stats or {}).get("total", 0),
                                    "facets": (stats or {}).get("facets", {}),
                                    "note": "统计模式不返回任何 IP/端口，仅用于了解指纹分布"})
        rows, seen = [], set()
        for m in matches or []:
            ip = m.get("ip") or m.get("ip_str")
            if not ip:
                continue
            port = m.get("port")
            t = "%s:%s" % (ip, port) if port else str(ip)
            if t in seen:
                continue
            seen.add(t)
            prod = (m.get("product") or "").strip()
            ver = (m.get("version") or "").strip()
            rows.append({"target": t, "ip": ip, "port": port,
                         "hint": (prod + " " + ver).strip(),
                         "country": m.get("country_code") or ""})
            if len(rows) >= limit:
                break
        return self._send(200, {"query": q, "count": len(rows),
                                "targets": [r["target"] for r in rows], "rows": rows})

    def _start(self):
        b = self._body()
        raw_targets = b.get("targets") or []
        if isinstance(raw_targets, str):
            raw_targets = re.split(r"[\r\n,;]+", raw_targets)
        targets = [t.strip() for t in raw_targets if t and t.strip() and not t.strip().startswith("#")]
        if not targets:
            return self._send(400, {"error": "目标列表为空"})
        # 目标数量默认不限制（0/未设置=不限）；如需限流可设环境变量 P2S_MAX_TARGETS
        targets = list(dict.fromkeys(targets))  # 去重，保持输入顺序
        try:
            max_targets = int(os.environ.get("P2S_MAX_TARGETS", "0") or 0)
        except ValueError:
            max_targets = 0
        if max_targets > 0 and len(targets) > max_targets:
            return self._send(400, {"error": "单次最多 %d 个目标（P2S_MAX_TARGETS 可调），请分批" % max_targets,
                                    "target_count": len(targets)})
        scope = b.get("scope") or []
        if isinstance(scope, str):
            scope = [x.strip() for x in re.split(r"[\r\n,;]+", scope) if x.strip()]
        if not scope:
            scope = derive_scope(targets)  # 粘贴即范围，无需手填授权范围
        authorized = bool(b.get("authorized"))
        local_only = all_targets_private(targets)
        if local_only:
            authorized = True  # 内网/回环目标（本地靶场）自动视为已授权，无需勾选
        else:
            publics = [t for t in targets if is_public_host(t)]
            if publics and not authorized:
                return self._send(400, {
                    "error": "存在公网目标，需要勾选授权确认（仅一次，浏览器会记住）："
                             "我确认对所填公网目标已获得书面授权。内网/回环目标无需勾选。",
                    "public_targets": publics[:20],
                    "public_count": len(publics)})
        mode = (b.get("mode") or "recon").lower()
        if mode not in ("recon", "oneclick"):
            mode = "recon"
        attack_ack = bool(b.get("attack_ack"))
        if mode == "oneclick" and not attack_ack:
            return self._send(400, {"error": "oneclick 会真实发起 RCE 利用，需勾选「我确认执行攻击（生成/回读 proof）」"})
        opts = {
            "mode": mode,
            "attack_ack": attack_ack,
            "deep": bool(b.get("deep")),
            "budget": max(1, min(8, int(b.get("budget") or 6))),
            "probe_sizes": (b.get("probe_sizes") or "0.5,1,2,4,8,16").strip(),
            "rounds": max(1, min(20, int(b.get("rounds") or 6))),
            "tries": max(1, min(5, int(b.get("tries") or 2))),
            "only": (b.get("only") or "id").strip()[:200],
            "concurrency": max(1, min(_max_workers(), int(b.get("concurrency") or 8))),
            "timeout": max(3, min(120, int(b.get("timeout") or 20))),
            "delay": max(0.0, min(10.0, float(b.get("delay") if b.get("delay") is not None else 0.3))),
            "insecure": bool(b.get("insecure")),
            "per_target_timeout": max(60, min(7200, int(b.get("per_target_timeout") or 1800))),
        }
        job = Job(targets, opts, authorized, scope)
        with JOBS_LOCK:
            JOBS[job.id] = job
        threading.Thread(target=job.run, daemon=True).start()
        return self._send(200, {"job_id": job.id, "total": job.total})

    def _export(self, snap, jid, kind):
        if kind == "export.csv" or kind == "export":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["target", "host", "public", "status", "rc", "duration_s",
                        "severity", "type", "url", "parameter", "evidence", "detail"])
            for t in snap["targets"]:
                if not t["findings"]:
                    w.writerow([t["url"], t["host"], t["public"], t["status"], t["rc"],
                                t["duration"], "", "", "", "", "", t.get("error", "")])
                for f in t["findings"]:
                    w.writerow([t["url"], t["host"], t["public"], t["status"], t["rc"],
                                t["duration"], f.get("severity"), f.get("type"),
                                f.get("url"), f.get("param"), (f.get("evidence") or "")[:500],
                                (f.get("detail") or "")[:500]])
            data = buf.getvalue().encode("utf-8-sig")
            return self._send(200, data, "text/csv; charset=utf-8",
                              {"Content-Disposition": 'attachment; filename="%s.csv"' % jid})
        data = json.dumps(snap, ensure_ascii=False, indent=1).encode("utf-8")
        return self._send(200, data, "application/json; charset=utf-8",
                          {"Content-Disposition": 'attachment; filename="%s.json"' % jid})


def main():
    ap = argparse.ArgumentParser(description="CVE-2026-109618 批量指纹与只读评估 GUI 控制台")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8899)
    a = ap.parse_args()
    os.makedirs(WORKROOT, exist_ok=True)
    if not os.path.isfile(P2S):
        sys.exit("找不到 attack/p2s_ext.py，请从工具包根目录运行")
    try:
        srv = ThreadingHTTPServer((a.host, a.port), Handler)
    except OSError as e:
        sys.exit("端口 %d 绑定失败（%s）。换端口重试：--port 8899" % (a.port, e))
    print("CVE-2026-109618 评估 GUI: http://%s:%d" % (a.host, a.port))
    print("结果目录: %s" % WORKROOT)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
