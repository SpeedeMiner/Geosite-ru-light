# Release gate hardening after v11.5

This change does not alter any released domain or category. The independently
pinned policy floor is the numbered v11.5 release DAT
(`9e13ae5da4122ea9567bb99c5c108503079083ed3eb5d7c97ca0f940ac9e068f`).
The rolling reference still prevents losses from later reviewed RU additions.
Neither a rolling DAT nor its matching checksum can independently authorize
a change relative to the pinned floor.

- All 17 non-RU categories must retain their exact typed rule sets in both
  comparisons. RU must retain coverage and approve new coverage in the
  existing approval manifest. A missing category, changed rule type or
  blocked routing decision is a hard failure.
- The checked-in reject/hold/confirmed TSV is required independently of the
  optional external inventory. Reject/hold protects the named host, not all
  children of a shared CDN. The explicit 4pda.to subtree and stream.kick.com
  policies are checked separately.
- A schedule run creates a review draft only for new RU rules absent from
  the rolling release, after the other checks have passed. Protected-category
  changes, losses and policy errors keep the report and block publication.
  To change protected categories or remove coverage deliberately, first
  implement a reviewed transition bound to a baseline digest. This change
  does not supply an automatic override.
- The build job has read-only repository permissions. A separate main-only
  publisher consumes the same run's five hashed assets and confirms the
  current main revision and rolling DAT digest before changing releases.
  Actions are pinned to the previously used upstream commits. The v11.5
  release is not recreated or altered by this workflow.
- The raw branch uses a normal fast-forward push and skips an identical
  tree. The rolling release skips unchanged assets. The DAT is verified
  at the resulting raw commit and the rolling asset digests are checked
  again after upload. The GitHub, raw and CDN channels are not atomic.
  CDN convergence is checked on both assets and reported separately.

Validation: Go tests exercise additions/removals/type changes in protected
categories, rolling drift, review outcomes, exclusions and the scheduled
review classification. The existing weekly writer and corporate-audit
schedules are unchanged.
