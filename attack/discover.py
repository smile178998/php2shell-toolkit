#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
discover.py -- CVE-2026-109618 资产发现与版本判定（Shodan / FOFA）

职责边界（重要）
----------------
本模块只做两件事：
  1) 通过 Shodan / FOFA 的**公开检索 API** 收集候选资产（被动，不接触目标）
  2) 可选地对候选做**一次**普通 GET，读取 X-Powered-By / Server 头，判定 PHP 版本
     → 只为了「按版本筛选」，不做任何 OOM / 变形请求

它**不会**对检索结果自动发起漏洞探测或利用。
对某个 IP 做 scan/exploit 之前，你必须自己确认对该 IP 有授权。

仅依赖标准库。
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
# 受影响版本矩阵：8.2 < 8.2.35 / 8.3 < 8.3.36 / 8.4 < 8.4.27 / 8.5 < 8.5.12
# ---------------------------------------------------------------------------
AFFECTED_MAX = {
    (8, 2): 35,
    (8, 3): 36,
    (8, 4): 27,
    (8, 5): 12,
}

VER_RE = re.compile(rb'PHP/(\d+)\.(\d+)\.(\d+)')
VER_RE_STR = re.compile(r'PHP/(\d+)\.(\d+)\.(\d+)')
# phpinfo 页面形态：<tr><td class="e">PHP Version </td><td class="v">8.2.12 </td>
VER_INFO_RE = re.compile(rb'PHP\s*Version\s*(?:</td>\s*<td[^>]*>\s*)?(\d+)\.(\d+)\.(\d+)')
VER_INFO_RE_STR = re.compile(r'PHP\s*Version\s*(?:</td>\s*<td[^>]*>\s*)?(\d+)\.(\d+)\.(\d+)')

DEFAULT_UA = 'php2shell-discover/1.0'


# ---------------------------------------------------------------------------
# 版本判定
# ---------------------------------------------------------------------------
def parse_php_version(text):
    """从任意文本/字节里抽 PHP 版本，返回 'x.y.z' 或 None。

    覆盖两种常见形态：
      Header / banner : Server: Apache/2.4 X-Powered-By: PHP/8.4.26
      phpinfo / 页面  : <td>PHP Version </td><td>8.2.12</td>
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
    返回 (verdict, note)
      AFFECTED   明确落在受影响区间
      PATCHED    明确已修复
      UNKNOWN    版本号无法解析，或超出已知矩阵（需人工查手册）
    """
    t = version_tuple(ver)
    if not t or len(t) < 3:
        return 'UNKNOWN', '版本未知'
    major, minor, patch = t[0], t[1], t[2]
    if major != 8:
        return 'UNKNOWN', '非 8.x，本矩阵未覆盖'
    limit = AFFECTED_MAX.get((major, minor))
    if limit is None:
        return 'UNKNOWN', '8.%d.x 不在已知矩阵内' % minor
    if patch < limit:
        return 'AFFECTED', '需 < 8.%d.%d，实测 8.%d.%d' % (minor, limit, minor, patch)
    return 'PATCHED', '已修复（需 < 8.%d.%d，实测 8.%d.%d）' % (minor, limit, minor, patch)


# ---------------------------------------------------------------------------
# 检索式构造
# ---------------------------------------------------------------------------
def shodan_query(php_version=None, extra=None):
    """构造 Shodan 检索式。"""
    parts = []
    if php_version:
        parts.append('"PHP/%s"' % php_version)
    else:
        parts.append('"X-Powered-By: PHP"')
    if extra:
        parts.append(extra)
    return ' '.join(parts)


def fofa_query(php_version=None, extra=None):
    """构造 FOFA 检索式（语法：header="..." / body="..."）。"""
    if php_version:
        q = 'header="X-Powered-By: PHP/%s"' % php_version
    else:
        q = 'header="X-Powered-By: PHP"'
    if extra:
        q = '(%s) && (%s)' % (q, extra)
    return q


# ---------------------------------------------------------------------------
# HTTP 基础
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
    返回 (matches, error)。每个 match 归一化为 dict。
    注意：Shodan 每页 100 条，1 次 query credit / 100 结果。
    """
    out = []
    for page in range(1, max(1, pages) + 1):
        url = 'https://api.shodan.io/shodan/host/search?' + urllib.parse.urlencode(
            {'key': api_key, 'query': query, 'page': page})
        try:
            status, _h, body = _http_get(url, timeout=timeout, proxy=proxy)
        except Exception as e:
            return out, 'Shodan 请求失败: %s' % e
        try:
            data = json.loads(body.decode('utf-8', 'replace'))
        except ValueError:
            return out, 'Shodan 返回非 JSON: %s' % body[:200]
        if 'error' in data:
            return out, 'Shodan 错误: %s' % data['error']
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
    只读统计：调用 /shodan/host/count，返回 (stats, error)。
    stats = {'total': int, 'facets': {name: [{value, count}, ...]}, 'query': str}
    刻意不返回任何主机 IP —— 用于了解某类指纹在全网的分布，不产出攻击目标清单。
    """
    url = 'https://api.shodan.io/shodan/host/count?' + urllib.parse.urlencode(
        {'key': api_key, 'query': query, 'facets': facets})
    try:
        status, _h, body = _http_get(url, timeout=timeout, proxy=proxy)
    except Exception as e:
        return None, 'Shodan 请求失败: %s' % e
    try:
        data = json.loads(body.decode('utf-8', 'replace'))
    except ValueError:
        return None, 'Shodan 返回非 JSON(HTTP %s): %s' % (status, body[:200])
    if 'error' in data:
        return None, 'Shodan 错误: %s' % data['error']
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
    """返回 (rows, error)。"""
    qb = base64.b64encode(query.encode('utf-8')).decode('ascii')
    params = {'key': api_key, 'qbase64': qb, 'size': min(max(size, 1), 10000),
              'fields': 'host,ip,port,server,title,header'}
    if email:
        params['email'] = email
    url = 'https://fofa.info/api/v1/search/all?' + urllib.parse.urlencode(params)
    try:
        status, _h, body = _http_get(url, timeout=timeout, proxy=proxy)
    except Exception as e:
        return [], 'FOFA 请求失败: %s' % e
    try:
        data = json.loads(body.decode('utf-8', 'replace'))
    except ValueError:
        return [], 'FOFA 返回非 JSON: %s' % body[:200]
    if data.get('error'):
        return [], 'FOFA 错误: %s' % (data.get('errmsg') or data.get('error'))
    rows = []
    for item in (data.get('results') or []):
        # fields 顺序: host,ip,port,server,title,header
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
# 归一化 / 去重 / 被动指纹
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
    对候选做一次普通 GET，只读响应头/前 64KB 里的版本串。
    这是唯一会接触目标的动作，且不带任何变形 payload。
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
    """给候选补上指纹与判定。limit=None 表示全部。"""
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
# 输出
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
    print('合计 %d 条，其中 AFFECTED %d 条' % (len(items), n_aff))
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
# 离线导入（--from-json）：便于缓存结果 / 无 key 时复算
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
