#!/usr/bin/env bash
# Use the same pinned compiler for CI and reproducible recovery.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
compiler_dir="$(mktemp -d)"
trap 'rm -rf "$compiler_dir"' EXIT
version=1.13.12
archive="sing-box-${version}-linux-amd64.tar.gz"
digest=1540533adb3df24f5ad5f14b5c7ca3dbc2401b10a1c1eb278fcadcada47ec6c4
curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 \
  -o "$compiler_dir/$archive" "https://github.com/SagerNet/sing-box/releases/download/v${version}/$archive"
printf '%s  %s\n' "$digest" "$compiler_dir/$archive" | sha256sum --check --strict
tar -xzf "$compiler_dir/$archive" -C "$compiler_dir" "sing-box-${version}-linux-amd64/sing-box"
python3 "$root/tools/build_geosite_srs.py" build --sing-box "$compiler_dir/sing-box-${version}-linux-amd64/sing-box" "$@"
