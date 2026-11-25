# RU audit follow-up: two unregistered domains — 25 November 2026

The investigation in [PR #46](https://github.com/SpeedeMiner/Geosite-ru-light/pull/46) identified two remaining unregistered domain rules:

- `domain:vtbkep.site`
- `domain:xn--90aifd0aza.site`

At 2026-11-25 06:52 UTC, [registration preflight](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/45563793321/artifacts/14997874948) checked IANA's RDAP bootstrap and used its listed `.site` registry, `rdap.radix.host`. Both responses were HTTP 404 with RDAP errorCode 404 and an explicit statement that the domain is available for registration. The zone WHOIS independently returned the same result; three authoritative zone nameservers returned NXDOMAIN with AA. The evidence is time-sensitive; reassess if a legitimate service is restored.

The initial preflight incorrectly queried Identity Digital rather than the IANA-listed `.site` RDAP endpoint. The later preflight above corrects that source. The preceding audit report's reference to an Identity Digital 404 as a registry response should likewise be read with this correction; the previous WHOIS and authoritative DNS observations remain separate.

Both names are appended to the existing `internal/ruunregistered` review list used by the RU subtree filter and release semantic gate. The filter blocks restored exact names, descendants and covering root suffixes from any source. The reviewed domains are not added to BLOCK. Existing Habr and 4pda exclusions and other categories retain their policies.

The [concluding audit report](https://github.com/SpeedeMiner/Geosite-ru-light/blob/audit/ru-domain-liveness/docs/audit-344-conclusion-2026-11-25.md) and its detailed evidence stay in the draft research PR. The [327 unresolved names](ru-audit-unknown-2026-11-25.txt) are preserved as a documentation-only monitoring snapshot; they are not removed or used as build input. `icq.com`, `telega.info` and `at.ua` are outside this change.
