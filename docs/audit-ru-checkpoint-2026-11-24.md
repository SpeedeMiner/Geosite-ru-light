# RU VPN audit recovery checkpoint — 2026-11-24

## Completed: initial recovery

- PR #46 was open and draft at head `16e1afb4ba9c861c3a6f3f05aa9461f8db6c2679` before this checkpoint.
- [Run 45417945474](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/45417945474), attempt 1, used that head and completed successfully in 27m52s. The complete jobs API response reports 47 successful jobs: plan, 45 measurements, collect.
- All 45 named shard artifacts, `vpn-fast-plan` and `vpn-fast-coverage` are listed. The collect log states it downloaded 45 shards. [Coverage artifact](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/45417945474/artifacts/14934187365), and the other artifacts, expire on 2026-12-08.
- The collect log reports 4,618 rules, 4,495 eligible names, and `two_or_more_asns: 4495`; this is **preliminary**, not independently validated coverage or proof of site availability.
- Release metadata for `geosite_RU.dat` reports SHA-256 `027939e3a31591bd48a57428c893a8237fe61352d90a8c3077b39366a3a3d0cc`, matching the plan log. This is metadata, not a new independent digest of downloaded bytes.

## Inspection findings

`tools/vpn_full_collect.py` counts distinct RU ASN values only if `verified_by_sources >= 2` and `asn_conflict` is false, but does not verify input shard completeness, duplicate observations, run/code provenance or manifest membership, and does not create the requested CSV or recheck plan. It cannot establish that each attempted probe completed correctly, nor independently validate VPN isolation. The fast wrapper catches per-domain exceptions and appends them as `network_error`; therefore a coverage count does not imply a valid HTTPS response. Its existing report says IPv4-only and redirects are not followed. No evidence of a content-level availability breakdown has yet been independently checked.

## Remaining

Inspect and preserve all raw artifacts; validate plan, sources, per-observation provenance and network isolation. Review the pinned VPN gate and DNS/TLS details; fix and test aggregation without triggering an unnecessary full run. Generate the requested reports and targeted recheck plan, run only justified rechecks, verify CI, and update PR #46. Do not modify rules, main, release, CDN, or other repositories. No domain removal is authorized. Keep PR draft.
