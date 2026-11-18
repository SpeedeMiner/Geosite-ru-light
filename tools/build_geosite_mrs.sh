#!/usr/bin/env bash
# Use the same official compiler for CI and offline reproduction.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
compiler_dir="$(mktemp -d)"
trap 'rm -rf "$compiler_dir"' EXIT
version=v1.19.27
archive="mihomo-linux-amd64-v1-${version}.gz"
digest=b922f6fc90a232b9265db1cc9c5206fee8479dc2047bb037ebf09bc3c9e3b352
if [[ "${1:-}" == --mihomo-archive ]]; then
  cp -- "${2:?path to the pinned mihomo archive required}" "$compiler_dir/$archive"
  shift 2
else
  curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 \
    -o "$compiler_dir/$archive" "https://github.com/MetaCubeX/mihomo/releases/download/$version/$archive"
fi
printf '%s  %s\n' "$digest" "$compiler_dir/$archive" | sha256sum --check --strict
gzip -dc -- "$compiler_dir/$archive" > "$compiler_dir/mihomo"
chmod 700 "$compiler_dir/mihomo"
python3 "$root/tools/build_geosite_mrs.py" build "$@" --mihomo "$compiler_dir/mihomo"
