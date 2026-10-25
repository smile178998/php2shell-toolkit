#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
discover.py -- CVE-2026-109618 asset discovery and version determination (Shodan / FOFA)

Responsibility boundary (important)
-----------------------------------
This module does only two things:
  1) Gather candidate assets via the **public search APIs** of Shodan / FOFA (passive, no contact with the target)
  2) Optionally perform **one** plain GET against a candidate, read the X-Powered-By / Server headers, and determine the PHP version
     -> only for "filtering by version"; no OOM / malformed requests of any kind

It does **not** automatically launch vulnerability probing or exploitation against search results.
Before you scan/exploit an IP, you must confirm yourself that you hold authorization for that IP.

Standard library only.
"""

import base64
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request

# ---------------------------------------------------------------------------
# Affected version matrix: 8.2 < 8.2.35 / 8.3 < 8.3.36 / 8.4 < 8.4.27 / 8.5 < 8.5.12
# ---------------------------------------------------------------------------
AFFECTED_MAX = {
    (8, 2): 35,
    (8, 3): 36,
    (8, 4): 27,
    (8, 5): 12,
}

VER_RE = re.compile(rb'PHP/(\d+)\.(\d+)\.(\d+)')
VER_RE_STR = re.compile(r'PHP/(\d+)\.(\d+)\.(\d+)')
# phpinfo page shape: <tr><td class="e">PHP Version </td><td class="v">8.2.12 </td>
VER_INFO_RE = re.compile(rb'PHP\s*Version\s*(?:</td>\s*<td[^>]*>\s*)?(\d+)\.(\d+)\.(\d+)')
VER_INFO_RE_STR = re.compile(r'PHP\s*Version\s*(?:</td>\s*<td[^>]*>\s*)?(\d+)\.(\d+)\.(\d+)')

DEFAULT_UA = 'php2shell-discover/1.0'


# ---------------------------------------------------------------------------
# Version determination
# ---------------------------------------------------------------------------
def parse_php_version(text):
    """Extract a PHP version from arbitrary text/bytes, return 'x.y.z' or None.

    Covers two common shapes:
      Header / banner : Server: Apache/2.4 X-Powered-By: PHP/8.4.26
      phpinfo / page  : <td>PHP Version </td><td>8.2.12</td>
    """
    if text is None:
        return None
    if isinstance(text, bytes):
        m = VER_RE.search(text) or VER_INFO_RE.search(text)
    else:
        m = VER_RE_STR.search(text) or VER_INFO_RE_STR.search(text)
    if not m:
        return None
    g = [x.decode('ascii', 'ignore') if isinstance(x, bytes) else x
         for x in m.groups()]
    return '%s.%s.%s' % tuple(g)


def version_tuple(ver):
    try:
        return tuple(int(x) for x in ver.split('.')[:3])
    except (ValueError, AttributeError):
        return None


def judge(ver):
    """
    Return (verdict, note)
      AFFECTED   clearly inside the affected range
      PATCHED    clearly patched
      UNKNOWN    version string cannot be parsed, or outside the known matrix (check the manual by hand)
    """
    t = version_tuple(ver)
    if not t or len(t) < 3:
        return 'UNKNOWN', 'version unknown'
    major, minor, patch = t[0], t[1], t[2]
    if major != 8:
        return 'UNKNOWN', 'not 8.x, this matrix does not cover it'
    limit = AFFECTED_MAX.get((major, minor))
    if limit is None:
        return 'UNKNOWN', '8.%d.x is not in the known matrix' % minor
    if patch < limit:
        return 'AFFECTED', 'requires < 8.%d.%d, measured 8.%d.%d' % (minor, limit, minor, patch)
    return 'PATCHED', 'patched (requires < 8.%d.%d, measured 8.%d.%d)' % (minor, limit, minor, patch)


# ---------------------------------------------------------------------------
# Search-query construction
# ---------------------------------------------------------------------------
def shodan_query(php_version=None, extra=None):
    """Build a Shodan search query."""
    parts = []
    if php_version:
        parts.append('"PHP/%s"' % php_version)
    else:
        parts.append('"X-Powered-By: PHP"')
    if extra:
        parts.append(extra)
    return ' '.join(parts)


def fofa_query(php_version=None, extra=None):
    """Build a FOFA search query (syntax: header="..." / body="...")."""
    if php_version:
        q = 'header="X-Powered-By: PHP/%s"' % php_version
    else:
        q = 'header="X-Powered-By: PHP"'
    if extra:
        q = '(%s) && (%s)' % (q, extra)
    return q


# ---------------------------------------------------------------------------
# HTTP basics
# ---------------------------------------------------------------------------
def _http_get(url, timeout=20.0, headers=None, proxy=None):
    req = urllib.request.Request(url, headers=headers or {'User-Agent': DEFAULT_UA})
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({'http': proxy, 'https': proxy}))
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    handlers.append(urllib.request.HTTPSHandler(context=ctx))
    opener = urllib.request.build_opener(*handlers)
    with opener.open(req, timeout=timeout) as r:
        return r.status, dict(r.headers), r.read(65536)


# ---------------------------------------------------------------------------
# Shodan
# ---------------------------------------------------------------------------
def shodan_search(api_key, query, pages=1, timeout=20.0, proxy=None):
    """
    Return (matches, error). Each match is normalized into a dict.
    Note: Shodan returns 100 per page, 1 query credit / 100 results.
    """
    out = []
    for page in range(1, max(1, pages) + 1):
        url = 'https://api.shodan.io/shodan/host/search?' + urllib.parse.urlencode(
            {'key': api_key, 'query': query, 'page': page})
        try:
            status, _h, body = _http_get(url, timeout=timeout, proxy=proxy)
        except Exception as e:
            return out, 'Shodan request failed: %s' % e
        try:
            data = json.loads(body.decode('utf-8', 'replace'))
        except ValueError:
            return out, 'Shodan returned non-JSON: %s' % body[:200]
        if 'error' in data:
            return out, 'Shodan error: %s' % data['error']
        matches = data.get('matches') or []
        for m in matches:
            out.append({
                'source': 'shodan',
                'ip': m.get('ip_str'),
                'port': m.get('port'),
                'hostnames': m.get('hostnames') or [],
                'server': (m.get('http') or {}).get('server'),
                'title': (m.get('http') or {}).get('title'),
                'banner_ver': parse_php_version(m.get('data') or ''),
            })
        if len(matches) < 100:
            break
        time.sleep(1.0)
    return out, None


def shodan_count(api_key, query, facets='country:8,port:10,product:6,version:6',
                 timeout=20.0, proxy=None):
    """
    Read-only statistics: calls /shodan/host/count and returns (stats, error).
    stats = {'total': int, 'facets': {name: [{value, count}, ...]}, 'query': str}
    Deliberately returns no host IPs -- meant to understand the global distribution of a fingerprint, not to produce an attack target list.
    """
    url = 'https://api.shodan.io/shodan/host/count?' + urllib.parse.urlencode(
        {'key': api_key, 'query': query, 'facets': facets})
    try:
        status, _h, body = _http_get(url, timeout=timeout, proxy=proxy)
    except Exception as e:
        return None, 'Shodan request failed: %s' % e
    try:
        data = json.loads(body.decode('utf-8', 'replace'))
    except ValueError:
        return None, 'Shodan returned non-JSON (HTTP %s): %s' % (status, body[:200])
    if 'error' in data:
        return None, 'Shodan error: %s' % data['error']
    facets_out = {}
    for name, rows in (data.get('facets') or {}).items():
        if isinstance(rows, list):
            facets_out[name] = [{'value': r.get('value'), 'count': r.get('count')}
                                for r in rows if isinstance(r, dict)]
    return {'total': data.get('total', 0), 'facets': facets_out, 'query': query}, None


# ---------------------------------------------------------------------------
# FOFA
# ---------------------------------------------------------------------------
def fofa_search(api_key, query, size=100, timeout=20.0, proxy=None, email=None):
    """Return (rows, error)."""
    qb = base64.b64encode(query.encode('utf-8')).decode('ascii')
    params = {'key': api_key, 'qbase64': qb, 'size': min(max(size, 1), 10000),
              'fields': 'host,ip,port,server,title,header'}
    if email:
        params['email'] = email
    url = 'https://fofa.info/api/v1/search/all?' + urllib.parse.urlencode(params)
    try:
        status, _h, body = _http_get(url, timeout=timeout, proxy=proxy)
    except Exception as e:
        return [], 'FOFA request failed: %s' % e
    try:
        data = json.loads(body.decode('utf-8', 'replace'))
    except ValueError:
        return [], 'FOFA returned non-JSON: %s' % body[:200]
    if data.get('error'):
        return [], 'FOFA error: %s' % (data.get('errmsg') or data.get('error'))
    rows = []
    for item in (data.get('results') or []):
        # fields order: host,ip,port,server,title,header
        if isinstance(item, dict):
            host, ip, port = item.get('host'), item.get('ip'), item.get('port')
            server, title, header = item.get('server'), item.get('title'), item.get('header')
        else:
            item = list(item) + [None] * (6 - len(item))
            host, ip, port, server, title, header = item[:6]
        ver = parse_php_version(header or '') or parse_php_version(server or '')
        rows.append({
            'source': 'fofa', 'host': host, 'ip': ip, 'port': port,
            'server': server, 'title': title,
            'banner_ver': ver,
        })
    return rows, None


# ---------------------------------------------------------------------------
# Normalization / dedupe / passive fingerprinting
# ---------------------------------------------------------------------------
def to_url(item, scheme=None):
    if item.get('host'):
        h = str(item['host'])
        if h.startswith('http://') or h.startswith('https://'):
            return h
    ip = item.get('ip') or item.get('host')
    port = item.get('port')
    if not ip:
        return None
    sch = scheme or ('https' if str(port) in ('443', '8443') else 'http')
    if port and str(port) not in ('80', '443'):
        return '%s://%s:%s/' % (sch, ip, port)
    return '%s://%s/' % (sch, ip)


def passive_fingerprint(url, timeout=10.0, proxy=None, verify_tls=False):
    """
    Perform one plain GET against a candidate; read the version string only from the response headers / first 64KB.
    This is the only action that touches the target, and it carries no malformed payload.
    """
    res = {'url': url, 'status': None, 'server': None, 'xpb': None,
           'php_ver': None, 'error': None}
    try:
        status, hdrs, body = _http_get(
            url, timeout=timeout,
            headers={'User-Agent': DEFAULT_UA, 'Accept': '*/*'},
            proxy=proxy)
        res['status'] = status
        low = {k.lower(): v for k, v in hdrs.items()}
        res['server'] = low.get('server')
        res['xpb'] = low.get('x-powered-by')
        res['php_ver'] = (parse_php_version(res['xpb'] or '')
                          or parse_php_version(res['server'] or '')
                          or parse_php_version(body))
    except Exception as e:
        res['error'] = str(e)
    return res


def enrich(items, timeout=10.0, proxy=None, limit=None):
    """Add fingerprints and verdicts to candidates. limit=None means all of them."""
    n = 0
    for it in items:
        if limit is not None and n >= limit:
            break
        url = it.get('url')
        if not url:
            continue
        fp = passive_fingerprint(url, timeout=timeout, proxy=proxy)
        it['probe'] = fp
        ver = fp.get('php_ver') or it.get('banner_ver')
        it['php_ver'] = ver
        it['verdict'], it['note'] = judge(ver)
        n += 1
    return items


def dedupe(items):
    seen, out = set(), []
    for it in items:
        key = (it.get('source'), it.get('ip') or it.get('host'), it.get('port'))
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def render(items, only_affected=False):
    hdr = '%-6s %-16s %-6s %-26s %-10s %-9s %s' % (
        'SRC', 'IP/HOST', 'PORT', 'URL', 'PHP', 'VERDICT', 'SERVER')
    print(hdr)
    print('-' * len(hdr))
    n_aff = 0
    for it in items:
        v = it.get('verdict', '-')
        if only_affected and v != 'AFFECTED':
            continue
        if v == 'AFFECTED':
            n_aff += 1
        print('%-6s %-16s %-6s %-26s %-10s %-9s %s' % (
            it.get('source', '')[:6],
            (it.get('ip') or it.get('host') or '')[:16],
            str(it.get('port') or '')[:6],
            (it.get('url') or '')[:26],
            (it.get('php_ver') or '?')[:10],
            v[:9],
            (it.get('probe', {}).get('server') or it.get('server') or '')[:28]))
    print()
    print('total %d entries, of which AFFECTED %d' % (len(items), n_aff))
    return n_aff


def emit_targets(items, path, only_affected=True):
    n = 0
    with open(path, 'w', encoding='utf-8') as fh:
        for it in items:
            if only_affected and it.get('verdict') != 'AFFECTED':
                continue
            u = it.get('url')
            if u:
                fh.write(u + '\n')
                n += 1
    return n


# ---------------------------------------------------------------------------
# Offline import (--from-json): handy for caching results / recomputing without keys
# ---------------------------------------------------------------------------
def load_from_json(path):
    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        for k in ('results', 'matches', 'rows', 'data'):
            if isinstance(data.get(k), list):
                data = data[k]
                break
    items = []
    for m in data if isinstance(data, list) else []:
        if not isinstance(m, dict):
            continue
        items.append({
            'source': m.get('source') or 'file',
            'ip': m.get('ip') or m.get('ip_str'),
            'port': m.get('port'),
            'host': m.get('host'),
            'hostnames': m.get('hostnames') or [],
            'server': m.get('server') or (m.get('http') or {}).get('server'),
            'title': m.get('title') or (m.get('http') or {}).get('title'),
            'banner_ver': parse_php_version(m.get('data') or m.get('header') or ''),
        })
    return items
