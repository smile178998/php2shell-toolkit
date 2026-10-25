#!/usr/bin/env bash
# build_profiles.sh — 便捷封装：批量生成 php2shell 外部 profile 库（profiles.json）
#
# 用法:
#   tools/build_profiles.sh                       # 用本机 php2shell 系列容器自动生成
#   tools/build_profiles.sh --out /tmp/p.json     # 指定输出
#   tools/build_profiles.sh --elf 8.4.26=/path/libphp.so --stage2-t 406
#
# 生成后可直接被 attack/p2s_ext.py 自动加载（搜索顺序：
#   包内 profiles.json -> ~/.php2shell/profiles.json -> ./profiles.json）
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
  echo "[*] 未指定参数，自动探测本机 php2shell 容器"
  mapfile -t CANDS < <(docker ps --format '{{.Names}}' 2>/dev/null | grep -E '^php2shell' || true)
  if [ ${#CANDS[@]} -eq 0 ]; then
    echo "[!] 没有找到 php2shell 容器；请用 --from-docker VER=容器 或 --from-elf VER=路径"
    exit 2
  fi
  for c in "${CANDS[@]}"; do
    ver=$(docker exec "$c" php -r 'echo PHP_VERSION;' 2>/dev/null || true)
    if [ -n "$ver" ]; then
      ARGS+=(--from-docker "${ver}=${c}")
    fi
  done
fi

echo "[*] 生成 $OUT"
$PY tools/build_profiles.py --out "$OUT" "${ARGS[@]}"
echo "[*] 完成。可执行以下命令校验加载:"
echo "    $PY attack/p2s_ext.py fingerprint -u http://127.0.0.1:8090/ --timeout 5 | head -3"
