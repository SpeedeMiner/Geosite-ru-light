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

## Artifact inspection

[Inspection run 45425949612](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/45425949612) downloaded the original coverage artifact and parsed its JSON. It found 4,495 host entries, 8,990 observations, 4,495 records each for AS12389 and AS12494, 45 job entries, and no missing observation-file counts. Exact repeated (ASN, exit IP, timestamp) keys per host: 0. Every observation had nonempty evidence and a timestamp. This is a structural check of the aggregate, not a raw-shard or network-isolation validation.

Observation states (not unique domains): 4,044 available, 2,851 review, 384 TLS error, 1,711 network error. The available state means the existing classifier found valid TLS and nonempty 2xx; it does not prove full application functionality. Reason counters are preserved in the inspection artifact. Raw observations remain in the original run. Follow-up must avoid interpreting observation counts as unique-site counts.

The inspection workflow is `.github/workflows/ru-audit-inspect.yml`. It accesses the previous artifact read-only and does not start new VPN measurements. No final report or recheck queue has been produced yet.
