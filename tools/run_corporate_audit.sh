#!/usr/bin/env bash
# Optional, read-only public metadata collection for human review.
set -euo pipefail

input="${1:-.corporate-audit-input}"
(
  cd "$input"
  sha256sum --check --strict geosite_RU.dat.sha256sum
)

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
base=https://github.com/SpeedeMiner/Geoip-ru-server/releases/download/latest-geoip-client-v41
fetch() {
  curl -fsSL --retry 1 --connect-timeout 12 --max-time 30 --max-filesize 2097152 "$1" -o "$2"
}
fetch "$base/geoip_RU_company_asn_core_bgp_prefixes.txt" "$tmp/core.txt"
fetch "$base/geoip_RU_company_asn_policy.tsv" "$tmp/policy.tsv"
(
  cd "$tmp"
  sha256sum --check --strict <<'CHECKSUMS'
4ca5332c4eb6b89ebfe3ecc0f6093a1d89681c39d145e568e127f8f1867f7e1e  core.txt
8a8026834fa309e7a2545fb866194a8713b4764ed8c8e79085abf293cfa3893b  policy.tsv
CHECKSUMS
)

go build -o "$tmp/geosite-delta" ./tools/geosite-delta
inventory=()
if fetch https://raw.githubusercontent.com/w1zardz/amnezia-vpn-russia-split-tunneling/master/data/external-candidates.json "$tmp/inventory.json" &&
  "$tmp/geosite-delta" discovery-inventory "$tmp/inventory.json" "$input/geosite_RU.dat" \
    data/v11-external-domain-review.tsv "$tmp/unreviewed.txt"; then
  inventory=(--inventory "$tmp/unreviewed.txt")
else
  echo "Optional external inventory unavailable; processing the curated HTTPS seeds only." >&2
fi

timeout 150s python3 tools/discover_corporate_domains.py \
  --seeds data/corporate_discovery_seeds.tsv --core-prefixes "$tmp/core.txt" \
  --asn-policy "$tmp/policy.tsv" --timeout 3 --max-candidates 200 --max-dns 60 \
  --max-inventory-dns 25 --workers 4 "${inventory[@]}" \
  --output geosite_RU_discovery_raw.tsv --status geosite_RU_discovery_status.json

"$tmp/geosite-delta" discovery-review geosite_RU_discovery_raw.tsv "$input/geosite_RU.dat" \
  data/v11-external-domain-review.tsv geosite_RU_discovered_candidates.md \
  geosite_RU_discovery_review_queue.tsv
