# Reviewed unregistered RU domains — 24 November 2026

This change excludes 29 currently unregistered domain suffixes from the RU routing category. These names are not added to BLOCK; all other categories retain their existing rules.

The proposal is based on [audit PR #46](https://github.com/SpeedeMiner/Geosite-ru-light/pull/46), its [final report](https://github.com/SpeedeMiner/Geosite-ru-light/blob/audit/ru-domain-liveness/docs/audit-ru-final-availability-2026-11-24.md), and [per-domain evidence](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/45456957539/artifacts/14951725470).

A targeted [registration preflight](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/45459256012) at 2026-11-24 18:24:57 UTC checked only these 29 names using IANA's RDAP bootstrap. All returned registry RDAP 404. For Verisign zones whose 404 response omitted a structured error code, exact registry WHOIS “No match” corroborated the result. The [preflight evidence](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/45459256012/artifacts/14952336391) contains individual endpoints and outcomes. No new registration was found.

The reviewed list is separate from permanent routing restrictions in `internal/ruunregistered/domains.go`. The existing RU subtree exclusion rejects each apex, descendants and any encompassing suffix; the semantic gate permits only the reviewed RU losses and rejects restored coverage. The unrelated `4pda.to` and `habr.com` policies remain. `cdn-tinkoff.com` is removed from local RU input and the approved-effective manifest. No other review candidates are excluded.

Registration may change. Recheck the affected name and review the exclusion if a legitimate service is restored; this policy is not a claim about the cause or date of registration ending. The original audit and observations remain in PR #46. This PR does not merge, publish or alter other repositories.


## Build verification

The [CI build](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/45459770303) compiled and tested DAT, SRS and MRS. An [independent exact typed comparison](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/45460106104/artifacts/14952816119) checked the published rolling DAT SHA-256 `027939e3a31591bd48a57428c893a8237fe61352d90a8c3077b39366a3a3d0cc` against the candidate `5a4f6b76814571995b36fe37f0613c0e856da9c98943e74f8313f77fa148ffc8`. It found RU 4,618 → 4,589, exactly the 29 listed typed rules removed, no RU additions, and no typed changes in other categories. Using the preserved audit manifest, unique applicable FQDN decreased 4,495 → 4,466. These are measured results against that exact release and build, not claims about future changing releases.

The filter and release gate tests cover all 29 roots, descendants, enclosing suffixes, re-import, unrelated losses and protected categories; the existing 4pda/Habr tests remain. The PR build did not publish.
