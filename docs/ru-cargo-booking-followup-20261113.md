# GeoSite RU v11.14 — cargo and booking follow-up

Baseline: published [Light v11.14](https://github.com/SpeedeMiner/Geosite-ru-light/releases/tag/v11.14) and [Server v11.14](https://github.com/SpeedeMiner/Geosite-ru-server/releases/tag/v11.14). Their DAT digests matched GitHub release asset metadata. Both have the four v11.14 exact aviation additions. Light has 3,188 RU and 44 BLOCK rules. Server has 3,076 RU rules and no other category.

## Queue for Russian-network verification

| Candidate for an exact rule | First-party public page | v11.14 coverage | Status |
| --- | --- | --- | --- |
| `www.volga-dnepr.com` | [Volga-Dnepr official cargo site](https://www.volga-dnepr.com/) | Neither RU nor BLOCK | Published page identified. Check public HTTPS from Russian networks. |
| `www.airbridgecargo.com` | [AirBridgeCargo Russian-language site](https://www.airbridgecargo.com/ru) | Neither RU nor BLOCK | Corporate site identified. Check public HTTPS from Russian networks. |
| `aviastartu.com` | [Aviastar-TU English-language cargo site](https://aviastartu.com/) and [Russian site](https://aviastartu.ru/) | Neither RU nor BLOCK for the .com site | Corporate page identified. Check public HTTPS from Russian networks. The .ru site is already covered. |

The sources above establish page identity, not reachability in Russia. The environment did not reach the Globalping API. Before proposing production rules, verify TLS and hostname validation from at least two Russian networks on the public paths above. Record redirects and separately check their target hosts. No login, tracking number, booking submission or purchase is needed.

## Not promoted

- `sales.nbc.aero` is linked by [Begishevo Airport](https://www.nbc.aero/passengers/), but the previous Russian review recorded a 403 browser challenge. The current web fetch also got 403. This does not prove an outage or filtering. Recheck in an ordinary browser from Russia before promoting.
- `booking.flyredwings.com` is listed in third-party directories. The [current Red Wings check-in page](https://flyredwings.com/check-in/) is covered, but the active production use and public TLS/HTTPS for the separate booking host were not verified.
- `yks.aero` and `www.yks.aero` remain on hold after the documented 403 and TLS results. See [v11.14 aviation follow-up](ru-aviation-followup-20261113.md).
- `aero.alrosa.ru` and `booking.aero.alrosa.ru` already match `domain:ru`. [ALROSA announced its site migration](https://aero.alrosa.ru/airline/news/new-website/). Existing rules for the old `.aero` hosts were not removed.
- The inspected S3/Swift endpoints at Selectel, Cloud.ru, VK Cloud, Yandex Cloud and MWS already match RU in both DATs, as do the previously published Dalli and KIT API hosts.

## Offline checks

Reprojecting the published Light DAT with the checked-in Server policy reproduced the published Server DAT byte-for-byte. A trial adding only the three cargo hostnames to Light RU yielded 3,191 Light RU and 3,079 Server RU rules, with exactly three new Server rules, no coverage losses, and no change to the non-RU Light categories. This was an in-memory trial, not a release build. No routing lists, inputs, workflows, GeoIP, production releases or tags were changed.
