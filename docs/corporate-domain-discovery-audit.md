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
