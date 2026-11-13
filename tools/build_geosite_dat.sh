#!/usr/bin/env bash
# Shared build path for CI and an offline replay from verified local inputs.
set -euo pipefail

filter="${1:?compiled ru-geosite-filter path required}"
export CATEGORY_FILE="${CATEGORY_FILE:-geosite_RU_categories.txt}"
export HYDRA_APPEND_FILE="${HYDRA_APPEND_FILE:-geosite_RU_hydra_appended_categories.txt}"
export RU_APPROVED_MANIFEST="${RU_APPROVED_MANIFEST:-data/v11-approved-effective-ru.txt}"
export RU_SUPPRESSED_ROOTS_REPORT="${RU_SUPPRESSED_ROOTS_REPORT:-geosite_RU_suppressed_roots.tsv}"
output="${OUTPUT_FILE:-geosite_RU.dat}"
new_sources="${NEW_SOURCES_REPORT_FILE:-geosite_RU_new_sources.txt}"
merged="$(mktemp)"
trap 'rm -f "$merged"' EXIT

python3 tools/build_ru_category_manifest.py
test -s "$CATEGORY_FILE"
test -s "$HYDRA_APPEND_FILE"
test -s v2fly-corporate-extra-domains.txt
cat "${LOCAL_RU_INPUT_FILE:-local/ru.txt}" v2fly-corporate-extra-domains.txt > "$merged"

"$filter" build \
  "${INPUT_FILE:-source-geosite.dat}" \
  "${HYDRA_INPUT_FILE:-hydra-geosite.dat}" \
  "${GRIMBIRD_INPUT_FILE:-grimbird-geosite.dat}" \
  "${MVR_INPUT_FILE:-mvrvntn-geosite.dat}" \
  "${YULARZHI_INPUT_FILE:-yularzhi-geosite.dat}" \
  "${VPNYASHA_INPUT_FILE:-vpnyasha-geosite.dat}" \
  "${KIRILL_INPUT_FILE:-kirill-geosite.dat}" \
  "${DIGNE_INPUT_FILE:-digne-geosite.dat}" \
  "${DAVOYAN_LEGACY_INPUT_FILE:-davoyan-category-ru-legacy.txt}" \
  "$CATEGORY_FILE" "$HYDRA_APPEND_FILE" "$merged" \
  "${LOCAL_BLOCK_INPUT_FILE:-local/block.txt}" \
  "${W1ZARDZ_RU_DIRECT_INPUT_FILE:-w1zardz-ru-direct-domains.txt}" \
  "${KYORESUAS_RU_STANDARD_INPUT_FILE:-kyoresuas-ru-standard-domains.txt}" \
  "$new_sources" "$output"
"$filter" validate "$output" "$HYDRA_APPEND_FILE"
test -s "$new_sources"
