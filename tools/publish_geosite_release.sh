#!/usr/bin/env bash
# Publish only the sealed, same-run bundle from the read-only build job.
set -euo pipefail

cd "${1:?approved bundle directory required}"
[[ "$GITHUB_REF" == refs/heads/main && "$GITHUB_EVENT_NAME" != pull_request ]]
[[ "$CANDIDATE_SHA" =~ ^[0-9a-f]{64}$ && "$BUNDLE_SHA" =~ ^[0-9a-f]{64}$ && "$ROLLING_SHA" =~ ^[0-9a-f]{64}$ ]]
[[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]]
files=(geosite_RU.dat geosite_RU.dat.sha256sum geosite_RU_categories.txt geosite_RU_hydra_appended_categories.txt geosite_RU_new_sources.txt)
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Compare canonical manifests instead of trusting paths in a downloaded file.
sha256sum -- "${files[@]}" > "$tmp/expected-manifest"
cmp release-bundle.sha256sum "$tmp/expected-manifest"
printf '%s  %s\n' "$BUNDLE_SHA" release-bundle.sha256sum | sha256sum --check --strict
printf '%s  geosite_RU.dat\n' "$CANDIDATE_SHA" | cmp geosite_RU.dat.sha256sum -
sha256sum --check --strict geosite_RU.dat.sha256sum

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
if [[ -n "${NUMBERED_RELEASE:-}" ]]; then
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
    gh release create "$NUMBERED_RELEASE" "${files[@]}" --repo "$GITHUB_REPOSITORY" \
      --draft --target "$GITHUB_SHA" --latest=false --title "GeoSite RU Light $NUMBERED_RELEASE" \
      --notes "Adds six exact ALT Linux hosts. No losses or changes to BLOCK or Hydra. DAT SHA-256: $NUMBERED_DAT_SHA. See $repo/blob/$GITHUB_SHA/docs/v11-6-alt-linux.md"
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
fi

# The existing release branch is kept as a normal fast-forward history.
gh auth setup-git --hostname github.com
git clone --quiet --depth=1 --single-branch --branch release "$repo.git" "$tmp/raw"
cp -- "${files[@]}" "$tmp/raw/"
git -C "$tmp/raw" add -- "${files[@]}"
if ! git -C "$tmp/raw" diff --cached --quiet; then
  git -C "$tmp/raw" -c user.name='github-actions[bot]' \
    -c user.email='41898282+github-actions[bot]@users.noreply.github.com' \
    commit -m "Publish verified GeoSite $CANDIDATE_SHA"
  git -C "$tmp/raw" push origin HEAD:refs/heads/release
fi
raw_commit="$(git -C "$tmp/raw" rev-parse HEAD)"
curl -fsSL --retry 2 --connect-timeout 10 --max-time 25 \
  "https://raw.githubusercontent.com/$GITHUB_REPOSITORY/$raw_commit/geosite_RU.dat" -o "$tmp/raw.dat"
cmp geosite_RU.dat "$tmp/raw.dat"

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
for file in "${files[@]}"; do
  want="sha256:$(sha256sum "$file" | cut -d' ' -f1)"
  [[ "$(asset_digest "$file")" == "$want" ]]
done
tag_sha="$(gh api "$api/git/ref/tags/$rolling" --jq '.object.sha')"
if [[ "$tag_sha" != "$GITHUB_SHA" ]]; then
  gh api --method PATCH "$api/git/refs/tags/$rolling" -f sha="$GITHUB_SHA" -F force=true >/dev/null
fi
[[ "$(gh api "$api/git/ref/tags/$rolling" --jq '.object.sha')" == "$GITHUB_SHA" ]]

# The CDN is eventually consistent. Report actual DAT+checksum parity, never
# infer it from the return code of a purge or from the checksum asset alone.
cdn="https://cdn.jsdelivr.net/gh/$GITHUB_REPOSITORY@release"
sync=false
check_cdn() {
  curl -fsSL --connect-timeout 6 --max-time 12 "$cdn/geosite_RU.dat" -o "$tmp/cdn.dat" &&
    cmp -s geosite_RU.dat "$tmp/cdn.dat" &&
    curl -fsSL --connect-timeout 6 --max-time 12 "$cdn/geosite_RU.dat.sha256sum" -o "$tmp/cdn.sha" &&
    cmp -s geosite_RU.dat.sha256sum "$tmp/cdn.sha"
}
if check_cdn; then
  sync=true
else
  for file in geosite_RU.dat geosite_RU.dat.sha256sum; do
    curl -fsS --connect-timeout 6 --max-time 15 \
      "https://purge.jsdelivr.net/gh/$GITHUB_REPOSITORY@release/$file" >/dev/null || true
  done
  for attempt in 1 2 3 4 5; do
    if check_cdn; then sync=true; break; fi
    if [[ "$attempt" != 5 ]]; then sleep 4; fi
  done
fi
if [[ "$sync" == false ]]; then
  echo "::warning::CDN DAT/checksum has not converged. Use the GitHub release or verified raw commit."
fi
printf '### Verified GeoSite distribution\n\n- GitHub Release: %s/releases/tag/%s\n- Verified raw commit: `%s`\n- DAT SHA-256: `%s`\n- jsDelivr DAT + checksum match: %s\n' \
  "$repo" "$rolling" "$raw_commit" "$CANDIDATE_SHA" "$sync" >> "$GITHUB_STEP_SUMMARY"
