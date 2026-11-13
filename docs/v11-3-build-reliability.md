# GeoSite RU Light v11.3 — build reliability

v11.3 is a build and policy-preservation change. The reference release is
v11.2 (3,086 RU rules, 23 Full, 43 BLOCK, and 16 appended Hydra categories).
No approval or local routing list is changed in this PR.

## Exact host policy

All RU RootDomain insertions go through the same guard. The manifest's
Full rules produce a label-bound ancestor index. An unreviewed suffix
that would cover one or more exact hosts is rejected before it can
participate in deduplication or pruning. BLOCK and Hydra are unaffected.
The build prints the suppressed names and writes
`geosite_RU_suppressed_roots.tsv` with the protected exact hosts.

A contradictory manifest containing both an approved covering suffix and
its protected Full rule fails with an explicit configuration error.
A deliberate widening must replace the affected Full approvals, update
the local input, and pass the release gate. The exact vendor gateways
on `ntprog.com` and the two Ozon Seller hosts remain protected.

Changing 17 Full rules into seven suffixes is a separate coverage
decision, not a refactor. The expected count would decrease by ten,
but the resulting policy would also cover previously unreviewed hosts.
For example, BaseALT describes `altlinux.org` services as ALT Linux Team
infrastructure, and the international ISPsystem and ispmanager legal
pages identify distinct international contracting entities. These facts
do not rule out individually justified suffixes, but do not establish
that all seven domains should be routed together. The v11.3 change keeps
all 23 exact rules.

- BaseALT: https://www.basealt.ru/alt-linux and https://www.basealt.ru/repository
- ISPsystem: https://www.ispsystem.com/contracts/license-agreement.html
- ispmanager: https://www.ispmanager.com/license-agreement

## Standalone tooling and source fallback

- Go is built and tested from this repository, with the previous v2ray
  and protobuf dependency versions pinned in `go.mod` and `go.sum`.
  The upstream v2fly checkout is still used for its category data.
- Run `go test ./...` and
  `python3 -m unittest discover -s tools -p test_fetch_geosite_sources.py`.
- Tier 1 is runetfreedom (DAT + published SHA-256) and Hydra. Neither is
  silently replaced with a cached copy. All Tier-2 sources are fetched
  live first. A failed transfer or an empty response can reuse a cache
  entry at most 21 days old, with matching source URL and content hash.
  The locally recorded hash detects cache corruption, not upstream
  authenticity. All reused data still goes through the normal build,
  validation and semantic release gate.
- Only validated main builds with fresh Tier-2 inputs save a snapshot
  set. A cold cache or a missing, expired or corrupt snapshot cannot
  produce a partial database. An optional external-candidate inventory
  failure does not block the core release gate.
- `geosite_RU_source_fetch.tsv` records each input's tier, fresh/fallback
  status, digest and original fetch time. Data, tooling and Go module
  changes now trigger builds on push to main.

## Next milestones

v11.4 can carry over the audit-only discovery work from PR #4 after
rebasing it onto the standalone layout. v11.5 can turn reviewable
weekly deltas into one Draft PR without treating a real build or
verification error as a successful run. Neither automation is part
of this build-reliability change.
