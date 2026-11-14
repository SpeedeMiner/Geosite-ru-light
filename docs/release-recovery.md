# Stage a previous GeoSite Light release

Use a numbered GitHub release for recovery, not a rolling URL, the current
release branch, or an unverified CDN response. The recovery registry records
the source commit and exact size and SHA-256 of each of the five published
assets for v11.5, v11.6 and v11.7. Extend it in a reviewed change after publishing
another numbered release. A checksum downloaded alongside a DAT is not the
independent trust anchor. The registry in a trusted checkout is.

From the GeoSite repository root, stage the numbered release in a new
directory. This downloads files without invoking Go, the build workflow or
the publisher.

```sh
python3 tools/stage_geosite_rollback.py v11.5 /tmp/geosite-light-v11.5-verified
(cd /tmp/geosite-light-v11.5-verified && sha256sum --check --strict geosite_RU.dat.sha256sum)
```

To verify a previously backed-up release directory without using the network:

```sh
python3 tools/stage_geosite_rollback.py v11.5 /tmp/geosite-light-v11.5-verified-offline \
  --from-directory /backup/geosite-light/v11.5
```

If any asset is missing or differs from its reviewed pin, the command fails
and does not expose a partial output. It refuses to overwrite a destination.
Copy the entire verified asset directory to private backup storage if you
want recovery without GitHub access.

## Rehearsal result

The five assets of both v11.5 and v11.6 were verified. In an isolated directory,
an active symlink was switched from v11.6 to v11.5 and then back to v11.6.
At each switch the active DAT and checksum matched the relevant numbered
release byte-for-byte. Neither GitHub publication nor a client reload was
part of the rehearsal.

| Snapshot | DAT bytes | DAT SHA-256 |
| --- | ---: | --- |
| v11.5 | 82,947 | `9e13ae5da4122ea9567bb99c5c108503079083ed3eb5d7c97ca0f940ac9e068f` |
| v11.6 | 83,092 | `b0be3f70f8a4950fde0aec2d237d8af5bbfc156c99079ac11cfb41f386d74107` |
| v11.7 | 83,200 | `b51429c5277c75cd40f889eeb8786937ac5f2df236764c0f60b7a700344879db` |

For v11.7, all five numbered assets were independently downloaded, staged,
and compared byte-for-byte with the verified build. The same files were
staged a second time with no network access. A rollback from v11.7 to v11.6
would remove the four exact rules listed in [the v11.7 release notes](v11-7-vendor-endpoints.md).

v11.5 does not contain the six exact ALT Linux hosts added by v11.6. The
recovery tool does not change the gate, move any tags, or publish an older
DAT to a rolling channel. A production rollback would be a separate
operational action and should account for the rules lost in the older
version and the time a CDN can continue serving cached bytes. This runbook
applies to Light only. The one-category Server artifact is not a substitute.

## Required check before a numbered release

The build job runs the numbered recovery check after the semantic release
gate. When the candidate DAT matches the approved numbered SHA-256, CI:

1. Packs the verified inputs into a temporary ZIP, restores the ZIP against
   the checked-in lock and rebuilds in a fresh directory with Go network
   module access disabled. All five release files must match byte-for-byte.
2. Downloads and stages the previously approved numbered release against the
   independent recovery registry. No rebuild is used for this step.
3. Sends a JSON receipt and its SHA-256 to the publishing job in the same
   run. That job verifies the receipt, lock, baseline, and the five candidate
   files before it calls GitHub. A missing or invalid receipt blocks that
   numbered candidate. It also checks the five published asset digests for
   the matching numbered snapshot.

The receipt is available in the PR audit or approved release bundle. The ZIP
containing upstream inputs is temporary and is not uploaded by CI. Save a
private copy using [the input backup commands](reproducible-build.md#keep-a-private-recovery-archive).
Scheduled discovery and rolling builds with a different DAT do not need a
new numbered recovery receipt.

To prepare a new numbered snapshot, set the four `NUMBERED_*` values at the
top of `.github/workflows/blank.yml` in the release PR. Use the reviewed
candidate SHA-256, the previous numbered tag from the recovery registry,
and a checked-in release notes file. Verify the PR's recovery step before
merging. After publishing, record the new numbered snapshot's exact five
sizes, digests and source commit in `data/geosite-recovery-releases.json`
before selecting it as a future rollback baseline.

## Derived sing-box rule-sets

The five pinned assets above remain the inputs to the numbered recovery
receipt. The SRS files are derived from the exact verified DAT, not from live
source lists. To reproduce them from a staged release, run
`bash tools/build_geosite_srs.sh --dat /path/to/staged/geosite_RU.dat --output-dir /path/to/srs`
on Linux x86-64. The script verifies the pinned compiler archive and checks
every rule-set by decompilation. When available, compare the resulting
`geosite_srs.sha256sum` with the numbered release's SRS manifest.
