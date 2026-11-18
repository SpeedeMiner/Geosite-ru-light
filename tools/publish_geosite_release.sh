#!/usr/bin/env bash
# Publish only the sealed, same-run bundle from the read-only build job.
set -euo pipefail

bundle="$(cd "${1:?approved bundle directory required}" && pwd -P)"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$bundle"
[[ "$GITHUB_REF" == refs/heads/main && "$GITHUB_EVENT_NAME" != pull_request ]]
[[ "$CANDIDATE_SHA" =~ ^[0-9a-f]{64}$ && "$BUNDLE_SHA" =~ ^[0-9a-f]{64}$ && "$ROLLING_SHA" =~ ^[0-9a-f]{64}$ ]]
[[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]]
core_files=(geosite_RU.dat geosite_RU.dat.sha256sum geosite_RU_categories.txt geosite_RU_hydra_appended_categories.txt geosite_RU_new_sources.txt)
srs_files="$(python3 "$root/tools/build_geosite_srs.py" verify-assets --dat geosite_RU.dat)"
mapfile -t srs_assets <<< "$srs_files"
mrs_files="$(python3 "$root/tools/build_geosite_mrs.py" verify-assets --dat geosite_RU.dat)"
mapfile -t mrs_assets <<< "$mrs_files"
rule_assets=("${srs_assets[@]}" "${mrs_assets[@]}")
files=("${core_files[@]}" "${rule_assets[@]}")
# The CDN branch exposes runtime rule-sets and the mihomo checksum manifest.
raw_files=(geosite_RU.dat geosite_mrs.sha256sum)
is_ruleset_name() {
  [[ "$1" =~ ^geosite_[A-Z0-9]+(-[A-Z0-9]+)*[.](srs|mrs)$ ]]
}
for file in "${rule_assets[@]}"; do
  if is_ruleset_name "$file"; then raw_files+=("$file"); fi
done
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Compare canonical manifests instead of trusting paths in a downloaded file.
sha256sum -- "${files[@]}" > "$tmp/expected-manifest"
cmp release-bundle.sha256sum "$tmp/expected-manifest"
printf '%s  %s\n' "$BUNDLE_SHA" release-bundle.sha256sum | sha256sum --check --strict
printf '%s  geosite_RU.dat\n' "$CANDIDATE_SHA" | cmp geosite_RU.dat.sha256sum -
sha256sum --check --strict geosite_RU.dat.sha256sum

# This check is local and precedes any release API call. The read-only
# build job must have rehearsed recovery for these exact numbered bytes.
# Scheduled builds only publish rolling; they never create or edit numbered assets.
if [[ "$GITHUB_EVENT_NAME" != schedule && -n "${NUMBERED_RELEASE:-}" ]]; then
  [[ "$NUMBERED_RELEASE" =~ ^v[0-9]+[.][0-9]+([.][0-9]+)?$ ]]
  [[ "${NUMBERED_DAT_SHA:-}" =~ ^[0-9a-f]{64}$ ]]
  if [[ "$CANDIDATE_SHA" == "$NUMBERED_DAT_SHA" ]]; then
    (
      cd "$root"
      python3 tools/verify_numbered_geosite_recovery.py verify-receipt \
        "$NUMBERED_RELEASE" "$NUMBERED_DAT_SHA" "${NUMBERED_RECOVERY_BASELINE:-}" "$bundle" "${RECOVERY_SHA:-}"
    )
  fi
fi

repo="https://github.com/$GITHUB_REPOSITORY"
api="repos/$GITHUB_REPOSITORY"
rolling=latest-optimized
main="$(gh api "$api/git/ref/heads/main" --jq '.object.sha')"
[[ "$main" == "$GITHUB_SHA" ]] || { echo "main changed; rerun the gate before publishing" >&2; exit 1; }

gh api "$api/releases/tags/$rolling" > "$tmp/release.json"
asset_digest() {
  jq -er --arg name "$1" '.assets[] | select(.name == $name) | .digest' "$tmp/release.json"
}
published_dat="$(asset_digest geosite_RU.dat)"
# On a retry the previously verified candidate may already be live. Refuse
# any third version. This also catches external updates between build/publish.
[[ "$published_dat" == "sha256:$ROLLING_SHA" || "$published_dat" == "sha256:$CANDIDATE_SHA" ]] || {
  echo "rolling release changed since the gate; rerun validation" >&2
  exit 1
}

# Publish a numbered snapshot from the same verified bundle. Subsequent runs
# verify its pinned DAT without trying to replace it with a newer rolling DAT.
if [[ "$GITHUB_EVENT_NAME" != schedule && -n "${NUMBERED_RELEASE:-}" ]]; then
  [[ "$NUMBERED_RELEASE" =~ ^v[0-9]+[.][0-9]+([.][0-9]+)?$ ]]
  [[ "$NUMBERED_DAT_SHA" =~ ^[0-9a-f]{64}$ ]]
  numbered_id() {
    gh api --paginate "$api/releases?per_page=100" |
      jq -rs --arg tag "$NUMBERED_RELEASE" 'add | .[] | select(.tag_name == $tag) | .id'
  }
  id="$(numbered_id)"
  if [[ -z "$id" ]]; then
    [[ "$CANDIDATE_SHA" == "$NUMBERED_DAT_SHA" ]] || {
      echo "candidate DAT is not the approved numbered snapshot" >&2
      exit 1
    }
    [[ "${NUMBERED_RELEASE_NOTES:-}" =~ ^docs/[a-zA-Z0-9][a-zA-Z0-9._-]+[.]md$ ]]
    test -s "$root/$NUMBERED_RELEASE_NOTES"
    gh release create "$NUMBERED_RELEASE" "${files[@]}" --repo "$GITHUB_REPOSITORY" \
      --draft --target "$GITHUB_SHA" --latest=false --title "GeoSite RU Light $NUMBERED_RELEASE" \
      --notes-file "$root/$NUMBERED_RELEASE_NOTES"
    id="$(numbered_id)"
  fi
  [[ "$id" =~ ^[0-9]+$ ]]
  gh api "$api/releases/$id" > "$tmp/numbered.json"
  [[ "$(jq -r '.prerelease' "$tmp/numbered.json")" == false ]]
  if [[ "$(jq -r '.draft' "$tmp/numbered.json")" == true ]]; then
    [[ "$CANDIDATE_SHA" == "$NUMBERED_DAT_SHA" ]]
    [[ "$(jq -r '.target_commitish' "$tmp/numbered.json")" == "$GITHUB_SHA" ]]
    for file in "${files[@]}"; do
      want="sha256:$(sha256sum "$file" | cut -d' ' -f1)"
      [[ "$(jq -er --arg name "$file" '.assets[] | select(.name == $name) | .digest' "$tmp/numbered.json")" == "$want" ]]
    done
    gh release edit "$NUMBERED_RELEASE" --draft=false --latest=false --repo "$GITHUB_REPOSITORY"
  fi
  gh api "$api/releases/tags/$NUMBERED_RELEASE" > "$tmp/numbered.json"
  jq -e --arg digest "sha256:$NUMBERED_DAT_SHA" --arg tag "$NUMBERED_RELEASE" \
    '.tag_name == $tag and .draft == false and .prerelease == false
      and any(.assets[]; .name == "geosite_RU.dat" and .digest == $digest)' \
    "$tmp/numbered.json" >/dev/null
  if [[ "$CANDIDATE_SHA" == "$NUMBERED_DAT_SHA" ]]; then
    numbered_digest() {
      jq -er --arg name "$1" '.assets[] | select(.name == $name) | .digest' "$tmp/numbered.json"
    }
    # Backfill derived assets only for this exact snapshot, preserving the
    # pinned recovery files and any already published numbered rule-set bytes.
    for file in "${core_files[@]}"; do
      want="sha256:$(sha256sum "$file" | cut -d' ' -f1)"
      [[ "$(numbered_digest "$file")" == "$want" ]]
    done
    missing_rulesets=()
    for file in "${rule_assets[@]}"; do
      want="sha256:$(sha256sum "$file" | cut -d' ' -f1)"
      if jq -e --arg name "$file" 'any(.assets[]; .name == $name)' "$tmp/numbered.json" >/dev/null; then
        [[ "$(numbered_digest "$file")" == "$want" ]] || {
          echo "numbered rule-set asset differs: $file" >&2
          exit 1
        }
      else
        missing_rulesets+=("$file")
      fi
    done
    if (( ${#missing_rulesets[@]} )); then
      gh release upload "$NUMBERED_RELEASE" "${missing_rulesets[@]}" --repo "$GITHUB_REPOSITORY"
      gh api "$api/releases/tags/$NUMBERED_RELEASE" > "$tmp/numbered.json"
    fi
    for file in "${files[@]}"; do
      want="sha256:$(sha256sum "$file" | cut -d' ' -f1)"
      [[ "$(numbered_digest "$file")" == "$want" ]]
    done
  fi
fi

# The existing release branch is kept as a normal fast-forward history.
gh auth setup-git --hostname github.com
git clone --quiet --depth=1 --single-branch --branch release "$repo.git" "$tmp/raw"
# Remove obsolete category files if the reviewed DAT changes its categories.
current_ruleset() {
  grep -Fxq -- "$1" <<< "$srs_files"$'\n'"$mrs_files"
}
git -C "$tmp/raw" ls-files -- 'geosite_*.srs' 'geosite_*.mrs' > "$tmp/raw-rulesets.txt"
while IFS= read -r old; do
  if is_ruleset_name "$old" && ! current_ruleset "$old"; then
    git -C "$tmp/raw" rm -- "$old"
  fi
done < "$tmp/raw-rulesets.txt"
for old in geosite_RU.dat.sha256sum geosite_RU_categories.txt \
  geosite_RU_hydra_appended_categories.txt geosite_RU_new_sources.txt geosite_srs.sha256sum; do
  if git -C "$tmp/raw" ls-files --error-unmatch -- "$old" >/dev/null 2>&1; then
    git -C "$tmp/raw" rm -- "$old"
  fi
done
cp -- "${raw_files[@]}" "$tmp/raw/"
git -C "$tmp/raw" add -- "${raw_files[@]}"
while IFS= read -r path; do
  [[ "$path" == geosite_RU.dat || "$path" == geosite_mrs.sha256sum ]] || is_ruleset_name "$path" || {
    echo "unexpected file in CDN branch: $path" >&2
    exit 1
  }
done < <(git -C "$tmp/raw" ls-files)
if ! git -C "$tmp/raw" diff --cached --quiet; then
  git -C "$tmp/raw" -c user.name='github-actions[bot]' \
    -c user.email='41898282+github-actions[bot]@users.noreply.github.com' \
    commit -m "Publish verified GeoSite $CANDIDATE_SHA"
  git -C "$tmp/raw" push origin HEAD:refs/heads/release
fi
raw_commit="$(git -C "$tmp/raw" rev-parse HEAD)"
[[ "$(git -C "$tmp/raw" ls-remote origin refs/heads/release | cut -f1)" == "$raw_commit" ]]
distribution_checks=(geosite_RU.dat geosite_RU.srs geosite_RU.mrs geosite_BLOCK.mrs geosite_mrs.sha256sum)
for file in "${distribution_checks[@]}"; do
  curl -fsSL --retry 2 --connect-timeout 10 --max-time 25 \
    "https://raw.githubusercontent.com/$GITHUB_REPOSITORY/$raw_commit/$file" -o "$tmp/raw-asset"
  cmp "$file" "$tmp/raw-asset"
done

changed=()
for file in "${files[@]}"; do
  want="sha256:$(sha256sum "$file" | cut -d' ' -f1)"
  have="$(asset_digest "$file" || true)"
  if [[ "$want" != "$have" ]]; then changed+=("$file"); fi
done
if (( ${#changed[@]} )); then
  gh release upload "$rolling" "${changed[@]}" --clobber --repo "$GITHUB_REPOSITORY"
fi
gh api "$api/releases/tags/$rolling" > "$tmp/release.json"
jq -r '.assets[].name | select(test("^geosite_[A-Z0-9]+(-[A-Z0-9]+)*[.](srs|mrs)$"))' \
  "$tmp/release.json" > "$tmp/rolling-rulesets.txt"
removed_rulesets=false
while IFS= read -r old; do
  if ! current_ruleset "$old"; then
    gh release delete-asset "$rolling" "$old" --repo "$GITHUB_REPOSITORY" --yes
    removed_rulesets=true
  fi
done < "$tmp/rolling-rulesets.txt"
if [[ "$removed_rulesets" == true ]]; then
  gh api "$api/releases/tags/$rolling" > "$tmp/release.json"
fi
for file in "${files[@]}"; do
  want="sha256:$(sha256sum "$file" | cut -d' ' -f1)"
  [[ "$(asset_digest "$file")" == "$want" ]]
done
tag_sha="$(gh api "$api/git/ref/tags/$rolling" --jq '.object.sha')"
if [[ "$tag_sha" != "$GITHUB_SHA" ]]; then
  gh api --method PATCH "$api/git/refs/tags/$rolling" -f sha="$GITHUB_SHA" -F force=true >/dev/null
fi
[[ "$(gh api "$api/git/ref/tags/$rolling" --jq '.object.sha')" == "$GITHUB_SHA" ]]

# Keep GitHub's Latest badge and the stable rolling URL. Change only metadata
# after the release assets and Git tag have been verified above.
rolling_title='Optimized RU GeoSite Light'
{
  printf 'The rolling GeoSite RU Light build. The download URL stays the same.\n\n'
  if [[ -n "${NUMBERED_RELEASE:-}" && "$CANDIDATE_SHA" == "$NUMBERED_DAT_SHA" ]]; then
    printf 'Current DAT matches [%s](%s/releases/tag/%s).\n\n' \
      "$NUMBERED_RELEASE" "$repo" "$NUMBERED_RELEASE"
  elif [[ -n "${NUMBERED_RELEASE:-}" ]]; then
    printf 'Current build: unnumbered rolling snapshot.\n\n'
    printf 'Latest configured numbered snapshot: [%s](%s/releases/tag/%s).\n\n' \
      "$NUMBERED_RELEASE" "$repo" "$NUMBERED_RELEASE"
  else
    printf 'Current build: unnumbered rolling snapshot.\n\n'
  fi
  printf 'For sing-box, download `geosite_RU.srs`, `geosite_BLOCK.srs` or individual categories below. Verify their digests with `geosite_srs.sha256sum`.\n\n'
  printf 'For mihomo, use the `geosite_*.mrs` domain providers with `geosite_mrs.sha256sum`.\n\n'
  printf -- '- Source commit: [`%s`](%s/commit/%s)\n- DAT SHA-256: `%s`\n' \
    "$GITHUB_SHA" "$repo" "$GITHUB_SHA" "$CANDIDATE_SHA"
} > "$tmp/rolling-notes.md"
rolling_id="$(jq -er '.id' "$tmp/release.json")"
gh api "$api/releases/latest" > "$tmp/latest.json"
if ! jq -e --arg title "$rolling_title" --rawfile notes "$tmp/rolling-notes.md" \
     --argjson id "$rolling_id" '.id == $id and .name == $title and .body == $notes' \
     "$tmp/latest.json" >/dev/null; then
  gh api --method PATCH "$api/releases/$rolling_id" \
    -f name="$rolling_title" -F body=@"$tmp/rolling-notes.md" -f make_latest=true >/dev/null
fi
gh api "$api/releases/latest" > "$tmp/latest.json"
jq -e --arg tag "$rolling" --arg title "$rolling_title" --rawfile notes "$tmp/rolling-notes.md" \
  --arg digest "sha256:$CANDIDATE_SHA" --argjson id "$rolling_id" \
  '.id == $id and .tag_name == $tag and .name == $title and .body == $notes
    and any(.assets[]; .name == "geosite_RU.dat" and .digest == $digest)' \
  "$tmp/latest.json" >/dev/null || {
    echo "rolling release metadata or Latest badge differs from the verified bundle" >&2
    exit 1
  }

# The CDN is eventually consistent. Spot-check runtime files and the MRS manifest.
cdn="https://cdn.jsdelivr.net/gh/$GITHUB_REPOSITORY@release"
sync=false
check_cdn() {
  local file
  for file in "${distribution_checks[@]}"; do
    curl -fsSL --connect-timeout 6 --max-time 12 "$cdn/$file" -o "$tmp/cdn-asset" || return 1
    cmp -s "$file" "$tmp/cdn-asset" || return 1
  done
}
if check_cdn; then
  sync=true
else
  for file in "${distribution_checks[@]}"; do
    curl -fsS --connect-timeout 6 --max-time 15 \
      "https://purge.jsdelivr.net/gh/$GITHUB_REPOSITORY@release/$file" >/dev/null || true
  done
  for attempt in 1 2 3 4 5; do
    if check_cdn; then sync=true; break; fi
    if [[ "$attempt" != 5 ]]; then sleep 4; fi
  done
fi
if [[ "$sync" == false ]]; then
  echo "::warning::CDN DAT/SRS/MRS has not converged. Use the GitHub release or verified raw commit."
fi
printf '### Verified GeoSite distribution\n\n- GitHub Release: %s/releases/tag/%s\n- Verified raw commit: `%s`\n- DAT SHA-256: `%s`\n- jsDelivr DAT + SRS/MRS spot checks match: %s\n' \
  "$repo" "$rolling" "$raw_commit" "$CANDIDATE_SHA" "$sync" >> "$GITHUB_STEP_SUMMARY"
