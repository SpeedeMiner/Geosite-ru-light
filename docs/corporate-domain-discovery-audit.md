# Corporate-domain discovery: GeoIP v41 CORE × GeoSite (audit only)

Status: proposed for PR CI and Monday schedule. **Never writes DIRECT, BLOCK, or approved-domain manifests.**

## Ground truth

Source is the published immutable-by-convention [Geoip-ru-server v41 release](https://github.com/SpeedeMiner/Geoip-ru-server/releases/tag/latest-geoip-client-v41), **not** a generic entire-RU GeoIP category.

- Policy: `geoip_RU_company_asn_policy.tsv`, released SHA256 `8a8026834fa309e7a2545fb866194a8713b4764ed8c8e79085abf293cfa3893b`
- Exact-origin CORE prefix list: `geoip_RU_company_asn_core_bgp_prefixes.txt`, SHA256 `9b2600280adb4a3622b3cb795225732b773a178455a302e4118c2263fc1b9b87`
- Policy snapshot includes **57 selected ASN rows**, **31 CORE_CORPORATE** and **25 SHARED_INFRA**; CORE covers **14 distinct company groups**. The other corporate/hosting categories are not treated as first-party origin evidence.
- Prefix rows have the format `CIDR # AS123,AS456`; mixed MOAS prefixes must contain at least one explicitly CORE ASN. Matched ASN and group are recorded as evidence, not a legal owner assertion.
- The GeoIP v41 inputs are pinned to released asset digests. An asset update must be reviewed and SHA pin changed explicitly.

## Discovery sources and restrictions

- `data/corporate_discovery_seeds.tsv` is a small explicit first-party HTTPS seed list across the 14 CORE groups plus CDN/education vendors.
- `tools/discover_corporate_domains.py` opens HTTPS 443 to **public addresses** of each seed with certificate validation and correct SNI. It does not follow redirects to other hosts.
- Extracts exact-host `subjectAltName` DNS names from live certificates and exact hosts in CSP directives `script-src`, `img-src`, `style-src`, `media-src`, `connect-src`, `font-src`, `worker-src`. Report-Only policies are marked separately.
- Also parses `<link rel="preconnect">` from at most 96 KiB of the seed HTML body. Wildcards `*.example.net` **are not widened** to `example.net`.
- No direct HTTP connection is made to a candidate domain, only DNS A/AAAA lookups for limited candidates. Public IP answers are compared with pinned CORE-origin prefixes. Core-hosted does **not** mean company-owned.
- Script has bounded timeout, maximum candidates, DNS count, HTTPS body size, and no external API key.
- CSP can reference global or advertising domains, a shared SAN can include unrelated hostnames, and corporate ASN can serve partners. All results are **review candidates only**, never `confirmed` based solely on a match.

## Semantic filtering and output

The new `geosite-delta discovery-review` mode uses the **actual newly built protobuf DAT**:

- Subtracts already covered `geosite:RU` according to both RootDomain and Full semantics;
- excludes `geosite:BLOCK` overlaps;
- excludes user-prohibited `4pda.to` and its subdomains;
- suppresses domains with existing `hold` or `reject` decisions from `data/v11-external-domain-review.tsv`;
- outputs `geosite_RU_discovered_candidates.md`, for human attribution, not a list to apply automatically.

Raw source observations and provenance are persisted in `geosite_RU_discovery_raw.tsv` and `geosite_RU_discovery_status.json`. Status includes seed failures, input SHA256, DNS budget, and counts; no real user DNS logs are collected.

On `pull_request` and weekly Monday `schedule`, an independent GitHub Actions step downloads the two pinned GeoIP v41 release assets and runs offline regression tests, live first-party discovery, and Go filtering. The step is `continue-on-error: true` so that intermittent external DNS/TLS failures cannot derail production release. Audit artifacts are uploaded independently for 14 days. **No discovered domain is appended to `local/ru.txt` by CI.**

## Future optional sources

- Local `dnscrypt-proxy`/`Xray`/router logs may reveal domain-level routing misses, but require user-provided anonymized input and a careful distinction between DNS result, geosite match, and actual selected routing rule. They are **not** part of public CI to protect privacy.
- APK `network_security_config.xml` and certificate pinning require licensing/redistribution review of mobile APKs and provenance; they are offline manual evidence sources, not unattended public CI inputs.
- crt.sh organization searches can discover CT SANs, but Organization fields can be absent (DV certs); avoid claiming that SAN co-tenancy proves common legal ownership. This step currently uses only direct TLS and CSP.

## Release policy

The existing v11.1 immutable release remains untouched. This PR changes **only research tooling**, Go audit mode, fixed input seed configuration and workflow report attachment. It must preserve the same RU/BLOCK protobuf output as the current release. If a new upstream candidate appears, it goes into the report, not into DIRECT.

Workflow logs and reports are authoritative for counts. Reachability and evidence freshness vary by run and are not inferred from a static description.


## First verified live run and false-positive triage

First successful GitHub Actions run: https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/43284267055
Refined, semantically equivalent CI: https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/43284912362

- 19 seeded first-party HTTPS hosts; 15 successfully probed, 4 bank domains (`sberbank.ru`, `tbank.ru`, `alfabank.ru`, `vtb.ru`) failed chain validation on the runner. No insecure bypass or unverifiable certificate fallback.
- Validated **283** exact CORE prefixes and **31 CORE ASN** against pinned release SHA256.
- 33 unique exact host observations (SAN/CSP/preconnect); 21 already effectively covered by candidate RU; no BLOCK matches; 12 uncovered and no prior hold/reject.
- All 12 uncovered domains came from **one** `selectel.ru` CSP and are globally operated dependencies (Google, YouTube, Zapier, Telegram, Statuspal etc.), without CORE matches. They are **not** reasonable automatic RU candidates.
- Updated report splits **prioritized candidates** (CORE evidence, exact SAN or at least two independent seed observations) from **low-evidence external dependencies** (single-source CSP/preconnect without CORE). For this run: **0 prioritized**, **12 weak**, **0 DIRECT changes**.
- The raw TSV preserves all candidates and evidence. The Markdown report prominently labels weak external dependencies and forbids automatic addition to DIRECT.
- Required offline Python/Go tests run in the fail-closed semantic CI step; live network collection and audit artifact upload are best-effort, so TLS/DNS outages cannot block production publication.

### Interpretation limits

A real certificate SAN or CSP directive does not prove that the host belongs to the same company. A website may intentionally use third-party CDN, fonts, analytics, video widgets or payment services. A DNS answer in a CORE prefix can also describe hosting or business partnership. Multiple technical signals increase the priority for further manual evidence review; they cannot replace proof of current first-party ownership and intended routing behavior.

**Explicit 4PDA policy remains unchanged:** `4pda.to` and all descendants are excluded from RU-DIRECT.


## Reality Scanner v2 — IP-first adaptation (2026-11-13)

Adapted *discovery ideas*, not the scanner's REALITY/SNI suitability algorithm:

- Source: https://github.com/SpeedeMiner/reality-scanner-v2 (`activeProbeIP`, `resolvePTRRaw`, `extractDomainsFromTLS`, `fetchShodanInternetDB`). Code here is a **rewritten independent Python implementation** under `tools/discover_corporate_ip_first.py`; no vendored scanner, no copied embedded API tokens, no REALITY probing.
- Input targets: A/AAAA of the 19 versioned first-party seed hostnames from `corporate_discovery_seeds.tsv`. **Only public IPs within the SHA-pinned GeoIP v41 CORE prefix file** survive. A manually curated IP TSV may also be supplied via `--curated-ips`; all rows are validated against the same CORE prefixes. No random sampling or sweep across any of the 283 prefixes.
- Per limited IP: reverse PTR, require **forward-confirmed DNS** (FCRDNS), and then probe HTTPS 443 with **verified TLS + SNI** using a known seed host or confirmed PTR host. Parse SAN exact DNS hosts only; no wildcard widening, insecure TLS fallback, or guessing SNI.
- Optional, keyless **Shodan InternetDB** IP hostname history (default disabled in CLI; CI capped to 3 IP requests). Observations are labelled `IP_SHODAN_HISTORY`; they remain historical OSINT, not ownership evidence.
- Network budgets: at most 12 selected CORE IPs in CI, 3 SSL seconds per connection, at most 3 SNI names per IP, 3 public OSINT requests, no more than 80 SAN names per certificate; `timeout 140s` bounds the full IP-first stage.
- Evidence schema: versioned `geosite_RU_discovery_site_raw.tsv` (direct first-party SAN/CSP), merged `geosite_RU_discovery_raw.tsv` (site+IP), `geosite_RU_discovery_status.json`, and `geosite_RU_ip_discovery_status.json`. Exact domain signal markers: `IP_PTR_FCRDNS`, `IP_TLS_SAN_VERIFIED`, `IP_SHODAN_HISTORY`.
- Both sources feed the already proven `geosite-delta discovery-review` semantic subtraction (RU/BLOCK + user ban `4pda.to` + prior hold/reject). Signals can raise **manual review priority** only. Even multiple signals or matched CORE ASN **never automatically add a RootDomain or Full rule**.
- All Python IP-first tests are mandatory in PR semantic CI. Live network probes are best-effort and cannot cause a production release failure, but missing network data must be described explicitly by the status JSON rather than assumed successful.

### Important source caveat

Original REALITY scanner may use `InsecureSkipVerify: true` for active handshake reconnaissance; this implementation **does not** copy that behavior. The original also includes apparent third-party API token defaults: these must be rotated/removed in the scanner repository separately, never imported into `Geosite-ru-light`. Hostname relationships inferred from a shared certificate, PTR or Shodan result are **not legal ownership evidence**.

### Manually curated IP option

An operator can use a local TSV with `IP<TAB>reason` rows, passed through `--curated-ips path.tsv`. Public/global and CORE-prefix membership are mandatory; `SHARED_INFRA`, private IPs, and arbitrary third-party addresses cause the tool to reject the file. No curated IP list is bundled or guessed. Manual curated inputs may be run locally before proposing them as publicly approved seed evidence.


## Verified IP-first CI after rewriting Reality Scanner (2026-11-13)

**Successful workflow:** https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/43288176902
**Published production v11.1 unchanged:** RU=3053, BLOCK=43, DAT=82237 bytes. Semantic delta against published release RU added=0, lost=0; BLOCK added=0, lost=0.

- `tools/discover_corporate_ip_first.py` is a new scoped replacement for the Reality Scanner v2 IP discovery path. No REALITY/H2 feasibility score, bulk ASN sweeps, insecure `utls` or embedded API keys.
- 26 public seed-resolved IPs fell inside pinned CORE prefixes; budget chose 12 for probing. 7 verified TLS handshakes, 2 forward-confirmed PTR records, 3 keyless InternetDB requests.
- **0 additional unique IP-first domains** were found in this run. Existing website-based collection still observed 33 exact domains (21 covered RU, 12 uncovered third-party dependencies from Selectel CSP, 0 priority candidates). No global CDN or parked domain is permitted into DIRECT from these signals.
- Two mandatory offline Python test suites: first-party TLS/CSP **5 tests**, IP-first **6 tests**. Go semantic filtering remains mandatory and BLOCK/4PDA regression gates pass.
- A test intentionally injected an untrusted `SHARED_INFRA` prefix into the IP matcher. We hardened `core_matches()` to **require the ASN's CORE_CORPORATE policy class even when a caller supplies malformed prefix sets**. The first CI with this new test failed, then the corrected implementation passed. Defence-in-depth is independent of the release-input validation.
- Successful audit artifact `geosite-ru-corporate-domain-discovery` contains `geosite_RU_discovery_site_raw.tsv`, merged `geosite_RU_discovery_raw.tsv`, `geosite_RU_discovery_status.json`, `geosite_RU_ip_discovery_status.json`, and `geosite_RU_discovered_candidates.md`.
- For privacy and operational safety, optional curated IPs are not bundled; the script's `--curated-ips` input remains opt-in and validates each entry. The next step for higher recall is carefully chosen additional **first-party IP seeds** with independently documented ownership, not faster/random scanning.

A lack of new findings must not be represented as full coverage of every technical domain. The discovery only observed public data accessible from the GitHub runner in this one bounded execution.


### Wider coverage without bulk scans

The IP-first sampler now allocates its bounded IP budget **round-robin across CORE company groups**, rather than taking the first 12 lexicographically sorted IPs. This avoids overrepresenting one operator when multiple first-party seed hosts share its infrastructure.

The repository provides `data/corporate_discovery_core_ips.tsv` with **no IPs prefilled**. Future maintainers may add an exact public IP and documentation of the first-party source. The CI invocation passes this file as `--curated-ips`, but every row is rejected unless it maps to the pinned CORE ASN prefixes. CIDR sweeps, ranges and non-global addresses are disallowed. Its SHA256 is written to `geosite_RU_ip_discovery_status.json` for reproducibility.

The tests cover group-balanced selection, rejection of shared-hosting/foreign IPs, FCrDNS spoofing resistance, SAN verification paths, and separation of historic Shodan hostnames from confirmed first-party services.


## Group-balanced final CI and inspected artifact (2026-11-13)

**Exact PR HEAD before this journal update:** `f7226f417a02809b066e67552d1862e7b0e91999`.
**Verified CI:** https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/43289096449 — success.
**Artifacts:** `geosite-ru-corporate-domain-discovery` + original `geosite-ru-v11-pr-audit`.

After round-robin CORE group selection, bounded activity observed:
- 12 of 26 CORE-qualified seed-resolved IPs were selected, **9 TLS chain-verified SNI probes**, **3 forward-confirmed PTRs**, **3 Shodan InternetDB** queries.
- Direct first-party SAN/CSP: 33 unique hosts.
- New IP-first evidence: 11 host observations; after de-duplication the combined total is **34** unique hosts, meaning **only one additional unique name**.
- That additional name is **`srv133-129-240-87.vk.com`**, forward-confirmed PTR for public CORE IP `87.240.129.133` (published origin **AS47541**, group VK/Mail.ru). Its current A addresses include that same IP. Because `vk.com` is already covered by RootDomain in RU, no new positive rule is required. Other TLS SAN corroborated `api.vk.com`, `stats.vk-portal.net`, `vk.me`, etc. without requiring new routing entries.
- Final semantic filter: **observed 34 / already RU 22 / BLOCK 0 / uncovered 12 / prioritized 0 / weak third-party CSP dependencies 12**; zero new valid corporate additions.
- Bank seeds that failed trust verification were **not** bypassed: the IP-first status records `SSLCertVerificationError` for `alfabank.ru`, `sberbank.ru`, and `tbank.ru`; an IPv6 Yandex Cloud target also had an ordinary connection error. Failures count as incomplete observations, not positive or negative company ownership proof.
- Two mandatory offline Python suites pass (**5 first-party tests + 7 IP-first tests**). Go semantic delta: **RU=3053, BLOCK=43, DAT=82237 bytes; newly_covered=0, lost=0 for RU and BLOCK**. All 57 pinned rules and user prohibition on `4pda.to` remain preserved.

**Interpretation:** This verifies the revised Reality Scanner IP-first method and group-balanced selection; it does **not** imply full corporate domain completeness. To expand recall, review more first-party seed hosts or explicitly documented CORE IP addresses. Do not invent server addresses or automatically import existing global CDN references.


## Iterative CORE DNS/IP recall without larger scan budgets (2026-11-13)

The original seed-to-IP conversion considered only the first eight DNS answers
from a first-party seed. That arbitrary truncation could discard a CORE address
after an initial run of foreign/shared IPs. Discovery now examines the entire
public DNS answer set for each curated seed, filters by the SHA-pinned CORE
prefix snapshot, **then** applies the global IP probe budget. No CIDR ranges
are expanded and no additional third-party hosts are contacted.

The IP-first audit now accepts `--rotation N`, defaulting to `0` for
backward-compatible deterministic selection. PR and scheduled CI pass
`--rotation "$GITHUB_RUN_NUMBER"`. The group order shifts each run; within
each group the IP pointer advances after every complete group-order cycle.
This avoids permanently starving addresses when group count and group size
share factors. Repeating the same run number against the same seed, DNS
and pinned CORE snapshots reproduces the selected sample.

`geosite_RU_ip_discovery_status.json` records `selection_rotation` and the
exact ordered `selected_seed_ips`, because seed DNS can change over time.
The step still probes **at most 12 public CORE IPs** and performs at most
**three keyless Shodan requests**. New regression tests cover a CORE record
beyond the first eight DNS answers and eventual sample coverage under a
smaller-than-group-count budget.

**Verification boundary:** code and tests are committed to the Draft PR.
Each new HEAD must pass offline Python tests and semantic Go checks in CI
before considering the implementation verified. This is not a justification
to add discovered names automatically to RU-DIRECT or to publish v11.2.


## Primary-source seed expansion (2026-11-13)

Four first-party HTTPS endpoints were added to the versioned
`data/corporate_discovery_seeds.tsv` source set (19 -> **23 seeds**).
Each was independently corroborated by the service operator's own docs:

| Seed | Corporate group | Primary operator reference |
|---|---|---|
| `disk.yandex.ru` | Yandex | [Yandex 360 network settings](https://yandex.ru/support/yandex-360/business/admin/ru/network-settings) |
| `api.disk.yandex.net` | Yandex | [Yandex 360 network settings](https://yandex.ru/support/yandex-360/business/admin/ru/network-settings) |
| `seller.ozon.ru` | Ozon | [Ozon seller platform agreement](https://docs.ozon.ru/legal/partners/service-provision/ozonology/agreement/) |
| `api.selectel.ru` | Selectel | [Selectel API authorization docs](https://docs.selectel.ru/api/authorization/) |

All four are **seed-only** sources, not proposed additions to the generated
RU database. Candidate hosts found in their SAN, CSP or HTML are still subject
to existing semantic DAT, BLOCK, 4PDA, hold/reject and exact-host reviews.
Any seed HTTPS/TLS failure is recorded as an incomplete observation, not
automatically bypassed. No authentication or protected APIs are called:
the scanner only makes the same bounded public `GET /` as for existing seeds.
The number of IP-first probes remains at 12, regardless of seed count.

A mandatory offline regression now loads the real seed manifest, verifies
the four expected host/group mappings and enforces uniqueness/budget.
Live audit results must be read from the CI artifacts; inclusion in this
file is not a claim that DNS, HTTPS or evidence collection succeeded.


## PR #4 production impact review — 2026-11-13

**Verified CI before the reporting improvement:**
[run 43293169602](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/43293169602),
commit `434877ea9554676cc24bd0eee78ddff5f4f52686`, build **success**.
The downloaded corporate discovery artifact was inspected, not inferred from the
PR description or a generic green job status.

- 23 curated first-party HTTPS seeds, **18 successful**, 5 TLS-chain-verified
  failures (Yandex Disk API plus four bank seeds), no insecure bypass.
- 96 site SAN/CSP/preconnect unique observations; 11 IP-first observations
  added only one further unique hostname; **97** combined.
- 30 eligible public CORE IPs, 12 selected; 9 verified TLS sessions,
  2 forward-confirmed PTR, 3 keyless InternetDB calls.
- Semantic result: **85 already RU-covered, 12 absent from RU, 0 BLOCK,
  0 prioritized missing corporate domains**.
- Inspection of the actual 18-category candidate `geosite_RU.dat` showed:
  **3 of those 12 already belong to other compiled categories**:
  `s.ytimg.com` and `www.youtube.com` via RootDomain coverage in
  `YOUTUBE`; `telegram.org` via RootDomain in `TELEGRAM`.
  **9 are absent from every category** but only have weak foreign Selectel
  CSP references (e.g. Google/AMP, Zapier, Statuspal), not independently
  verified first-party RU ownership. Other-category overlap is *not*
  equivalent to the RU routing rule and does not justify promoting a domain.
- Published/candidate semantic parity: **RU=3053, BLOCK=43, 16 additional
  Hydra categories, 0 newly covered and 0 lost in every category**.
  The PR has **zero production additions** and is research-only.

### How candidates could eventually reach the RU release

The candidate pipeline is deliberately separate:

1. `discover_corporate_domains.py` and `discover_corporate_ip_first.py`
   collect provenance-bearing raw observations, not approvals.
2. `geosite-delta discovery-review` uses the *built* DAT to eliminate
   existing RU/BLOCK coverage, apply the standing 4PDA prohibition and
   hold/reject decisions, and classify missing RU domains.
3. New reporting also shows overlap with **other** compiled categories and
   writes `geosite_RU_discovery_review_queue.tsv`. Every row starts
   `review_decision=UNREVIEWED,auto_direct=NO`, including priority rows.
4. For a future genuinely missing first-party service: independently verify
   the operator's published domain/endpoints, the reason for RU-DIRECT,
   and the minimal `full:` versus `domain:` scope. Record a traceable
   human decision, update the relevant reviewed source input and the pinned
   `data/v11-approved-effective-ru.txt` allowance **in a separate
   release-change review**. Approval alone does not inject a rule:
   the build must have an intentionally changed, versioned positive input.
5. Rebuild, run protobuf semantic checks, require no BLOCK or unrelated
   category drift, and allow a release only through existing production
   gates. The published `v11.1` tag is never overwritten.

The manifest lists *permitted effective additions*, not automatically
discovered domains. PR #4 does **not** modify positive sources, approvals,
`main`, `release`, or the published DAT. This distinction matters:
merging the audit by itself will not cause the release to accumulate 97,
12, 9 or even 1 rule.

**Release decision:** the PR can be considered an optional, bounded research
collector after its new CI passes, but there is currently **no evidence-based
RU coverage delta to promote**. Avoid importing foreign CSP references
merely to increase rule counts.
