#!/usr/bin/env bash
# build_profiles.sh — convenience wrapper: batch-generate the php2shell external profile library (profiles.json)
#
# Usage:
#   tools/build_profiles.sh                       # auto-generate from local php2shell containers
#   tools/build_profiles.sh --out /tmp/p.json     # specify output
#   tools/build_profiles.sh --elf 8.4.26=/path/libphp.so --stage2-t 406
#
# After generation it is auto-loaded by attack/p2s_ext.py (search order:
#   package profiles.json -> ~/.php2shell/profiles.json -> ./profiles.json)
set -euo pipefail
cd "$(dirname "$0")/.."

PY=${PYTHON:-python3}
OUT="profiles.json"
ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    *) ARGS+=("$1"); shift ;;
  esac
done

if [ ${#ARGS[@]} -eq 0 ]; then
  echo "[*] no arguments given, auto-detecting local php2shell containers"
  mapfile -t CANDS < <(docker ps --format '{{.Names}}' 2>/dev/null | grep -E '^php2shell' || true)
  if [ ${#CANDS[@]} -eq 0 ]; then
    echo "[!] no php2shell containers found; use --from-docker VER=container or --from-elf VER=path"
    exit 2
  fi
  for c in "${CANDS[@]}"; do
    ver=$(docker exec "$c" php -r 'echo PHP_VERSION;' 2>/dev/null || true)
    if [ -n "$ver" ]; then
      ARGS+=(--from-docker "${ver}=${c}")
    fi
  done
fi

echo "[*] generating $OUT"
$PY tools/build_profiles.py --out "$OUT" "${ARGS[@]}"
echo "[*] done. Run the following command to verify loading:"
echo "    $PY attack/p2s_ext.py fingerprint -u http://127.0.0.1:8090/ --timeout 5 | head -3"
