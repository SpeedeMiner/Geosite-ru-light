# Reproduce the GeoSite DAT from reviewed inputs

The build has two modes.

- Pull requests, main pushes and manual builds use
  `data/geosite-inputs.lock.json`. The file fixes the v2fly checkout and
  all 11 input files by revision, exact size and SHA-256. For GitHub release
  assets the record also carries the release tag, asset ID and upstream
  digest observed at review. The release URL is not a trust anchor: the
  expected bytes are checked after download. A mismatch is a hard failure.
- Monday runs use the live sources and keep the existing bounded Tier-2
  fallback. They produce a JSON comparison of source hashes and the v2fly
  revision against the lock, and run the routing-policy gate as before.
  They can open the existing review draft for unreviewed RU additions, but
  never publish directly. The live report does not change the lock or
  authorize a release. Reviewed upstream updates are promoted by updating
  the lock in a PR, along with routing approvals when needed.

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
