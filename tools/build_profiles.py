#!/usr/bin/env python3
"""build_profiles.py — batch-generate profiles.json (external profile library) from symbols results

Usage:
  # Extract symbols from a local docker container and write profiles.json
  python3 tools/build_profiles.py --out profiles.json \
      --from-docker 8.4.26=php2shell-8426 \
      --from-docker 8.2.35=php2shell-fixed

  # Generate from an existing libphp.so
  python3 tools/build_profiles.py --out profiles.json \
      --from-elf 8.4.26=/path/to/libphp.so --stage2-t 406

  # Print only (do not write to disk)
  python3 tools/build_profiles.py --from-docker 8.4.26=php2shell-8426 --dry-run

Notes:
  * Generated entries contain only the fields symbols can provide (ht_size / zif_offset / dtor_offset / htdata_offset).
  * htdata_offset and stage2_t are calibration results and cannot be derived from the symbol table: htdata_offset comes from symbols'
    .data scan (this tool follows that), and stage2_t must be backfilled manually after a calibrate hit (--stage2-t).
  * rce_ok defaults to true; if the build has been measured to only DoS, manually set it to false in profiles.json.
  * When a name matches the built-in PROFILE_DB, the built-in one wins (the loader does not overwrite it).
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
    """kind: docker|elf ; spec: container[:path] or elf path"""
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
        sys.stderr.write(f"[!] symbols failed ({kind}:{spec} rc={r.returncode})\n")
        sys.stderr.write((r.stdout or "")[-800:] + (r.stderr or "")[-800:] + "\n")
        return None
    with open(tmp, "r", encoding="utf-8") as fh:
        prof = json.load(fh)
    os.remove(tmp)
    return prof


def main():
    ap = argparse.ArgumentParser(description="generate the php2shell external profile library")
    ap.add_argument("--out", default="profiles.json", help="output file (default profiles.json)")
    ap.add_argument("--from-docker", action="append", default=[], metavar="VER=CONTAINER[:PATH]")
    ap.add_argument("--from-elf", action="append", default=[], metavar="VER=/path/libphp.so")
    ap.add_argument("--stage2-t", type=int, default=None, help="backfill stage2_t (calibration hit value, e.g. 406)")
    ap.add_argument("--rce-ok", choices=["true", "false"], default="true", help="rce_ok defaults to true")
    ap.add_argument("--dry-run", action="store_true", help="print only, do not write the file")
    a = ap.parse_args()

    jobs = [("docker", s) for s in a.from_docker] + [("elf", s) for s in a.from_elf]
    if not jobs:
        ap.error("provide at least one --from-docker or --from-elf")

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
            sys.stderr.write(f"[!] format should be VER=SPEC, skipping: {item}\n")
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
        sys.stderr.write("[!] no entries were generated\n")
        return 2

    text = json.dumps(merged, indent=2, ensure_ascii=False, sort_keys=True)
    if a.dry_run:
        print(text)
    else:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"[*] wrote {a.out} ({len(merged)} profiles)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
