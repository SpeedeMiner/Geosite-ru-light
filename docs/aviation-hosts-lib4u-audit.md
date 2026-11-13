# Aviation host follow-up and lib4u source audit

This change adds only eight exact aviation hostnames to RU. The Domodedovo
procurement portal is tracked separately in [PR #24](https://github.com/SpeedeMiner/Geosite-ru-light/pull/24).
No suffix expansion, BLOCK edits, imported IP routes, or workflow changes.

## Aviation checks

All eight were absent from RU in the published Light and Server v11.11 DATs.
They each returned HTTP 200 with verified TLS on anonymous GET from AS12389,
AS3216 and AS207957 on 2026-11-13. These are public pages; no sign-in,
check-in transaction, purchase or payment was attempted.

| Exact host | Public path | Attribution | RU measurement |
|---|---|---|---|
| `aaq.aero` | `/` | [Anapa Airport](https://t.me/SouthAirports) | [200 × 3](https://api.globalping.io/v1/measurements/2lTBRC038BAskVgU800021Uqb) |
| `aer.aero` | `/flights/online-schedule/` | [Sochi Airport public flight board](https://t.me/s/favt_info/4874) | [200 × 3](https://api.globalping.io/v1/measurements/2PM8fXOg1W0E6ZBqb00021Uqa) |
| `ikar.aero` | `/ru/webcheckin/` | [Ikar public check-in page](https://gelaero.ru/passengers/registration/online-registration/) | [200 × 3](https://api.globalping.io/v1/measurements/2Z1clcAJnfbkcESK800021UqZ) |
| `krr.aero` | `/` | [Krasnodar Airport](https://t.me/s/favt_info/4874) | [200 × 3](https://api.globalping.io/v1/measurements/2w1VMPEVUeMSJFudV00021Uqa) |
| `mcx.aero` | `/board/?departure` | [Makhachkala Airport public flight board](https://mcx.aero/board/?departure=) | [200 × 3](https://api.globalping.io/v1/measurements/2Um4hm1Pk3qDtOTCb00021Uqa) |
| `ticket.rusline.aero` | `/websky-check-in/` | [RusLine public check-in page](https://www.rusline.aero/services/upravlenie-bronirovaniem-onlayn/) | [200 × 3](https://api.globalping.io/v1/measurements/2ELGN4TbkPLYNcGWI00021UqY) |
| `www.nbc.aero` | `/` | [Begishevo Airport www host](https://www.nbc.aero/) | [200 × 3](https://api.globalping.io/v1/measurements/2QLvy7PA7bJzyhXql00021UqY) |
| `zia.aero` | `/` | [Zhukovsky Airport public flight board](https://zia.aero/) | [200 × 3](https://api.globalping.io/v1/measurements/2Kmv3sjH3RLMLbbvC00021UqY) |

`booking.alrosa.aero` and `azimut.alrosa.aero` redirect but presented expired
certificates in all three networks. The working new booking name,
`booking.aero.alrosa.ru`, is covered by `domain:ru`.
`sales.nbc.aero` returned a 403 browser challenge and the checked Yakutsk
flight board returned 403. Neither is added. The old `svo.aero` returned
a valid redirect to the already covered `svo.su`; the legacy alias is not
added in this batch.

## lib4u source snapshot

Reviewed [commit 204fe32785ed452bdb510c9945694d3184614a43](https://github.com/lib4u/amnezia-tunneling-ru/tree/204fe32785ed452bdb510c9945694d3184614a43).
All three JSON digests matched the corresponding release asset metadata at
inspection time. The [build workflow](https://github.com/lib4u/amnezia-tunneling-ru/blob/204fe32785ed452bdb510c9945694d3184614a43/.github/workflows/build.yml)
sources domains from v2fly DLC including `private`; the export flattens
exact/suffix semantics and removes attributes. Of 2,289 rows in
`amnezia.json`, 2,172 are unique normalized dotted hostnames after omitting
99 special-use rows and 18 remaining single labels.

- Light v11.11 covers all 2,172 in RU. Nine also match BLOCK, including
  `mc.yandex.ru`, `appmetrica.yandex.net` and `stats.rustore.ru`. These are
  existing overlaps; keep BLOCK precedence where intended in the client.
- Server v11.11 covers 2,146. The 26 differences all fall under the
  [Server exclusion suffixes](https://github.com/SpeedeMiner/Geosite-ru-server/blob/49d7ecae95fbebc21561b5028a4f40d1cf9c8ec7/data/exclude-server-suffixes.txt),
  e.g. `routerlogin.com`, `miwifi.com` and `ts.net`; they are not coverage
  gaps to fill. Neither the eight rules above nor `market.dme.aero`
  appear in this lib4u snapshot.
- `amnezia-ip.json` has 12,902 IPv4 CIDRs from v2fly GeoIP.
  `amnezia-ip-lite.json` has 1,295 IPv4 CIDRs. Of those, 430 have no overlap
  with the full file's address set, including `1.1.1.1/32`. The lite builder
  uses DNS, IP-to-ASN expansion and address-specific fallbacks, so the
  result is not a strict geographic subset or evidence of RU ownership.

No lib4u import is proposed for GeoSite or GeoIP.
