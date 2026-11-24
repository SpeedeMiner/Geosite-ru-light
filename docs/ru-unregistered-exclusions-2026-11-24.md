# Reviewed unregistered RU domains — 24 November 2026

This change excludes 29 currently unregistered domain suffixes from the RU routing category. These names are not added to BLOCK; all other categories retain their existing rules.

The proposal is based on [audit PR #46](https://github.com/SpeedeMiner/Geosite-ru-light/pull/46), its [final report](https://github.com/SpeedeMiner/Geosite-ru-light/blob/audit/ru-domain-liveness/docs/audit-ru-final-availability-2026-11-24.md), and [per-domain evidence](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/45456957539/artifacts/14951725470).

A targeted [registration preflight](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/45459256012) at 2026-11-24 18:24:57 UTC checked only these 29 names using IANA's RDAP bootstrap. All returned registry RDAP 404. For Verisign zones whose 404 response omitted a structured error code, exact registry WHOIS “No match” corroborated the result. The [preflight evidence](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/45459256012/artifacts) contains individual endpoints and outcomes. No new registration was found.

The reviewed list is separate from permanent routing restrictions in `internal/ruunregistered/domains.go`. The existing RU subtree exclusion rejects each apex, descendants and any encompassing suffix; the semantic gate permits only the reviewed RU losses and rejects restored coverage. The unrelated `4pda.to` and `habr.com` policies remain. `cdn-tinkoff.com` is removed from local RU input and the approved-effective manifest. No other review candidates are excluded.

Registration may change. Recheck the affected name and review the exclusion if a legitimate service is restored; this policy is not a claim about the cause or date of registration ending. The original audit and observations remain in PR #46. This PR does not merge, publish or alter other repositories.
