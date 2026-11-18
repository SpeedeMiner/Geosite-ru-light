# Reproduce the GeoSite DAT from reviewed inputs

The build has two modes.

- Pull requests, main pushes and manual builds use
  `data/geosite-inputs.lock.json`. The file fixes the v2fly checkout and
  all 11 input files by revision, exact size and SHA-256. For GitHub release
  assets the record also carries the release tag, asset ID and upstream
  digest observed at review. The release URL is not a trust anchor: the
  expected bytes are checked after download. A mismatch is a hard failure.
- Monday runs (00:00 UTC) build from live sources and compare their hashes
  and the v2fly revision against the lock. With all sources freshly fetched
  and the semantic gate and DAT/SRS/MRS checks passing, they update the
  `latest-optimized` rolling release and the CDN `release` branch.
  Identical assets are not uploaded again. A cached Tier-2 fallback is
  usable only for diagnostics and review, never for scheduled publication.
  Unapproved RU additions can open or update the existing review draft
  without changing public artifacts. The schedule does not change the lock
  or create or modify numbered releases. Reviewed source changes can still
  be pinned in a PR, with routing approvals when needed.

The initial lock was verified against the exact inputs used to build v11.6.
It does not change any rules, release tags or numbered assets. The JSON
input manifest is included in CI artifacts for inspection. A stale or
unavailable pinned URL fails closed; the lock itself does not archive bytes.

## Offline replay

Prepare the repository checkout, the Go version in `go.mod` and its
populated module cache. Keep a copy of the eleven payloads, using the
`output` filenames in the lock, in a separate directory. The payloads
may come from an earlier verified download or an offline mirror.
Prepare a clean checkout of the locked v2fly commit in
`domain-list-community` before disconnecting.

Then from the GeoSite repository root:

```sh
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
python3 tools/locked_geosite_inputs.py materialize /absolute/path/to/input-payloads
go build -o /tmp/ru-geosite-filter ./tools/ru-geosite-filter
bash tools/build_geosite_dat.sh /tmp/ru-geosite-filter
sha256sum geosite_RU.dat
```

This checks the v2fly commit and tracked data, then stages the files before
installing the verified inputs. The final DAT for the initial v11.6 lock is
83,092 bytes with SHA-256
`b0be3f70f8a4950fde0aec2d237d8af5bbfc156c99079ac11cfb41f386d74107`.

The same build script is used by Actions. A replay of the compiler is
offline; the production release gate separately fetches and checks the
current rolling release and the pinned policy floor.

## Reproduce mihomo MRS offline

MRS outputs are derived from the exact verified DAT, one `behavior: domain`
file per category. Exact hosts are plain names and suffixes use
`+.example.com` so they match the base domain and its subdomains. The
exporter refuses to publish if mihomo drops, adds, duplicates, or changes
the type of any rule, even when two overlapping entries would match the
same traffic after deduplication.

Before going offline, save the official Linux x86-64 archive pinned in
[`tools/build_geosite_mrs.sh`](../tools/build_geosite_mrs.sh)
and the `geosite_mrs.sha256sum` from the same trusted release as the DAT.
The wrapper checks the archive against its hardcoded SHA-256 before
decompressing and running it. Given the archive and DAT locally, no download
is needed:

```sh
bash tools/build_geosite_mrs.sh \
  --mihomo-archive /offline/mihomo-linux-amd64-v1-v1.19.27.gz \
  --dat /offline/geosite_RU.dat --output-dir /tmp/geosite-mrs
cmp /offline/geosite_mrs.sha256sum /tmp/geosite-mrs/geosite_mrs.sha256sum
(cd /tmp/geosite-mrs && sha256sum --check --strict /offline/geosite_mrs.sha256sum)
```

If you have the downloaded MRS files instead, check the complete file set
and manifest against the DAT's categories without running the compiler:

```sh
python3 tools/build_geosite_mrs.py verify-assets \
  --dat /offline/geosite_RU.dat --output-dir /offline/published-mrs
```

This last command verifies the file set and hashes. For an independent
content check, reproduce the MRS files and compare the trusted manifest
as shown above. The numbered recovery receipt still covers the original
five core files. MRS files and their manifest are separately checked and
sealed with those files before publication.

## Keep a private recovery archive

A pinned download can disappear. After reviewing the lock and materializing
the inputs, create a ZIP in an operator-controlled location:

```sh
python3 tools/geosite_input_archive.py create . domain-list-community /backup/geosite-v11.6-inputs.zip
sha256sum /backup/geosite-v11.6-inputs.zip
```

The ZIP contains the reviewed lock, all 11 original payloads and the v2fly
`data/` tree with its license. It is not a Git checkout or a copy of the Go
toolchain/module cache. The command checks each payload's size and SHA-256
against the trusted lock, verifies the v2fly checkout, and reopens the ZIP to
check it before exposing it. Use private storage for the upstream payloads.
Do not add the archive to Git or publish it as a release asset.

When updating the locked v2fly revision, first put the new revision in the
lock, check out that exact commit, and run the following command. Review the
new fingerprint alongside the revision, then regenerate the archive.

```sh
python3 tools/geosite_input_archive.py fingerprint domain-list-community
```

Store its output in `domain_list_community.archive_tree_sha256`. Both the
standard locked build and archive replay check the fingerprint when required
by their mode.

To restore after a source disappears, start with a fresh GeoSite checkout
containing the trusted lock for this snapshot. Use a new output directory
and ensure the checkout has no existing `domain-list-community` directory.

```sh
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
python3 tools/geosite_input_archive.py restore /backup/geosite-v11.6-inputs.zip /tmp/geosite-v11.6-restored
cp -R /tmp/geosite-v11.6-restored/domain-list-community ./domain-list-community
python3 tools/locked_geosite_inputs.py materialize-archive /tmp/geosite-v11.6-restored
go build -o /tmp/ru-geosite-filter ./tools/ru-geosite-filter
bash tools/build_geosite_dat.sh /tmp/ru-geosite-filter
sha256sum geosite_RU.dat
```

The restore rejects unexpected names, duplicate entries, non-regular files,
size mismatches, modified source bytes, and an archive whose embedded lock
differs from the reviewed checkout. It does not run code from the archive.
The two independent v11.6 replays from the restored ZIP both matched the
published DAT byte-for-byte (83,092 bytes, 18 categories, 3,092 RU rules).

See [release recovery](release-recovery.md) if you need a previous published
DAT immediately rather than a source replay.
