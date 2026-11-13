# GeoSite RU v11.14 — cargo and booking follow-up

Baseline: published [Light v11.14](https://github.com/SpeedeMiner/Geosite-ru-light/releases/tag/v11.14) and [Server v11.14](https://github.com/SpeedeMiner/Geosite-ru-server/releases/tag/v11.14). Their DAT digests matched GitHub release asset metadata. Both have the four v11.14 exact aviation additions. Light has 3,188 RU and 44 BLOCK rules. Server has 3,076 RU rules and no other category.

## Verified exact RU rules

Anonymous HTTPS GETs on 2026-11-13 at 16:07 UTC from AS12389 (Kostroma),
AS3216 (Ufa) and AS207957 (Moscow or Novosibirsk). All nine requests
returned 200 with authorized TLS and the exact hostname in the certificate
SAN. The responses were public carrier pages and none was an HTTP redirect.
No login, tracking number, booking submission or purchase was used.

| Exact hostname | First-party page | Public path and measurement | Certificate issuer |
| --- | --- | --- | --- |
| `aviastartu.com` | [Aviastar-TU English-language cargo homepage](https://aviastartu.com/) | [`/` · 200 / 200 / 200](https://api.globalping.io/v1/measurements/28Q10KMt2TP2CoDam00021Utb) | Let’s Encrypt YR2 |
| `www.airbridgecargo.com` | [AirBridgeCargo Russian-language cargo homepage](https://www.airbridgecargo.com/ru) | [`/ru` · 200 / 200 / 200](https://api.globalping.io/v1/measurements/2WBMumEsUh402kzzv00021Utb) | Let’s Encrypt YE2 |
| `www.volga-dnepr.com` | [Volga-Dnepr official cargo homepage](https://www.volga-dnepr.com/) | [`/` · 200 / 200 / 200](https://api.globalping.io/v1/measurements/2IPjCuSOK45Z3He5S00021Utb) | Let’s Encrypt YR1 |

All three names were absent from RU in both v11.14 DATs and from BLOCK in Light.

## Not promoted

- `sales.nbc.aero` is linked by [Begishevo Airport](https://www.nbc.aero/passengers/), but the previous Russian review recorded a 403 browser challenge. The current web fetch also got 403. This does not prove an outage or filtering. Recheck in an ordinary browser from Russia before promoting.
- `booking.flyredwings.com` is listed in third-party directories. The [current Red Wings check-in page](https://flyredwings.com/check-in/) is covered, but the active production use and public TLS/HTTPS for the separate booking host were not verified.
- `yks.aero` and `www.yks.aero` remain on hold after the documented 403 and TLS results. See [v11.14 aviation follow-up](ru-aviation-followup-20261113.md).
- `aero.alrosa.ru` and `booking.aero.alrosa.ru` already match `domain:ru`. [ALROSA announced its site migration](https://aero.alrosa.ru/airline/news/new-website/). Existing rules for the old `.aero` hosts were not removed.
- The inspected S3/Swift endpoints at Selectel, Cloud.ru, VK Cloud, Yandex Cloud and MWS already match RU in both DATs, as do the previously published Dalli and KIT API hosts.

## Build scope

Add only these three full rules to the local RU source and approval manifest.
No suffix expansion, BLOCK edits, upstream pin changes, or GeoIP changes.
The Server projection retains a single RU category.
