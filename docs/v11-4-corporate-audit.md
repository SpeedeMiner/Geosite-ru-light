# GeoSite RU Light v11.4 — corporate domain review

This change adds an independent read-only Actions job for pull requests
and the weekly scheduled build. Its only routing input is the validated
GeoSite DAT and checksum uploaded by the build. It does not write local
rules, approvals, release assets or the DAT. Failure of live evidence
collection does not block the release. v11.3 and older tags are unchanged.

## Inputs and scope

- GeoIP v41 supplies 283 exact origin prefixes and a 56-ASN policy:
  31 CORE_CORPORATE and 25 SHARED_INFRA. Only CORE origins are used as
  evidence. The release asset URLs and both byte hashes are pinned.
  The current CORE asset differs from the older snapshot in PR #4.
- 27 fixed public HTTPS seeds cover 22 groups. The audited inputs are
  the verified seed certificate SAN, explicit CSP origins, and HTML
  preconnect entries. Wildcards are not widened, redirects are not
  followed, and only curated seeds receive HTTPS connections.
- Optional external inventory candidates are first filtered against
  the actual DAT, prior decisions, and the 4PDA exclusion. At most
  25 remaining candidates get DNS attribution within a total cap of
  60 candidate DNS lookups. No candidate receives an HTTP request.
- Beget, Timeweb, MTS and Rostelecom expand the seed groups, not the
  CORE origin policy. First-party sources: https://beget.com/ru,
  https://timeweb.cloud/docs, https://mts.ru/, https://rt.ru/.
- PR #4's IP-first probing and InternetDB path are not used for this
  milestone. PR #4 itself remains an independent historical draft.

## Output

The corporate audit artifact holds the raw TSV, status JSON, Markdown
report and review queue. The report distinguishes existing RU and BLOCK
coverage, overlaps with other categories, and weak third-party evidence.
All queued names start with UNREVIEWED and NO for automatic DIRECT.
Failed seeds are counted in the status, and incomplete coverage is
called out in the report and Actions summary.
CSP/preconnect references alone remain weak even when observed across
multiple companies. Only a CORE hosting match or exact SAN raises priority.

Even an exact TLS SAN or a CORE match is not legal ownership proof. A
rule needs a separate review and explicit changes to the rule list and
approval manifest. Weekly automatic draft PRs are a separate milestone.
