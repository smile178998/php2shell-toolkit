#!/usr/bin/env python3
"""build_profiles.py — 用 symbols 的结果批量生成 profiles.json（外部 profile 库）

用法：
  # 从本地 docker 容器提取符号，写入 profiles.json
  python3 tools/build_profiles.py --out profiles.json \
      --from-docker 8.4.26=php2shell-8426 \
      --from-docker 8.2.35=php2shell-fixed

  # 从现成 libphp.so 生成
  python3 tools/build_profiles.py --out profiles.json \
      --from-elf 8.4.26=/path/to/libphp.so --stage2-t 406

  # 只打印（不落盘）
  python3 tools/build_profiles.py --from-docker 8.4.26=php2shell-8426 --dry-run

说明：
  * 生成的条目只有 symbols 能给出的字段（ht_size / zif_offset / dtor_offset / htdata_offset）。
  * htdata_offset 与 stage2_t 属于「标定」结果，符号表无法推出：htdata_offset 由 symbols 的
    .data 扫描给出（本工具沿用），stage2_t 需用 calibrate 命中后人工回填（--stage2-t）。
  * rce_ok 默认为 true；如该版本经实测只能 DoS，请在 profiles.json 里手工改为 false。
  * 与内置 PROFILE_DB 同名时以内置为准（loader 不覆盖）。
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)
P2S = os.path.join(PKG, "attack", "p2s_ext.py")


def run_symbols(kind, spec):
    """kind: docker|elf ; spec: container[:path] 或 elf 路径"""
    tmp = os.path.join(PKG, ".sym.tmp.json")
    if os.path.exists(tmp):
        os.remove(tmp)
    cmd = [sys.executable, P2S, "symbols"]
    if kind == "docker":
        cmd += ["--docker", spec]
    else:
        cmd += ["--elf", spec]
    cmd += ["--out", tmp]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0 or not os.path.exists(tmp):
        sys.stderr.write(f"[!] symbols 失败（{kind}:{spec} rc={r.returncode}）\n")
        sys.stderr.write((r.stdout or "")[-800:] + (r.stderr or "")[-800:] + "\n")
        return None
    with open(tmp, "r", encoding="utf-8") as fh:
        prof = json.load(fh)
    os.remove(tmp)
    return prof


def main():
    ap = argparse.ArgumentParser(description="生成 php2shell 外部 profile 库")
    ap.add_argument("--out", default="profiles.json", help="输出文件（默认 profiles.json）")
    ap.add_argument("--from-docker", action="append", default=[], metavar="VER=CONTAINER[:PATH]")
    ap.add_argument("--from-elf", action="append", default=[], metavar="VER=/path/libphp.so")
    ap.add_argument("--stage2-t", type=int, default=None, help="回填 stage2_t（标定命中值，如 406）")
    ap.add_argument("--rce-ok", choices=["true", "false"], default="true", help="rce_ok 默认 true")
    ap.add_argument("--dry-run", action="store_true", help="只打印，不写文件")
    a = ap.parse_args()

    jobs = [("docker", s) for s in a.from_docker] + [("elf", s) for s in a.from_elf]
    if not jobs:
        ap.error("至少给一个 --from-docker 或 --from-elf")

    merged = {}
    if os.path.exists(a.out) and not a.dry_run:
        try:
            with open(a.out, "r", encoding="utf-8") as fh:
                merged = json.load(fh)
            if not isinstance(merged, dict):
                merged = {}
        except Exception:
            merged = {}

    ok = 0
    for kind, item in jobs:
        if "=" not in item:
            sys.stderr.write(f"[!] 格式应为 VER=SPEC，跳过：{item}\n")
            continue
        ver, spec = item.split("=", 1)
        ver, spec = ver.strip(), spec.strip()
        prof = run_symbols(kind, spec)
        if not prof:
            continue
        p = {
            "ht_size": prof.get("ht_size"),
            "htdata_offset": prof.get("htdata_offset"),
            "zif_offset": prof.get("zif_offset"),
            "dtor_offset": prof.get("dtor_offset"),
            "rce_ok": a.rce_ok == "true",
            "label": f"{ver} ({kind}:{spec})",
        }
        if a.stage2_t is not None:
            p["stage2_t"] = a.stage2_t
        merged[ver] = p
        ok += 1
        print(f"[+] {ver}: ht_size={p['ht_size']} htdata=0x{p['htdata_offset']:X} "
              f"zif=0x{p['zif_offset']:X} dtor=0x{p['dtor_offset']:X}")

    if not ok:
        sys.stderr.write("[!] 没有任何条目生成\n")
        return 2

    text = json.dumps(merged, indent=2, ensure_ascii=False, sort_keys=True)
    if a.dry_run:
        print(text)
    else:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"[*] 已写入 {a.out}（{len(merged)} 个 profile）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
