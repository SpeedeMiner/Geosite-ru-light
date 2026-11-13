# Russian airport and logistics endpoints

All names below are absent in the published v11.12 Light and Server RU DATs.
The comparison also checked BLOCK in Light. Measurements are anonymous
HTTPS GET requests from Russian AS12389, AS3216 and AS207957. A code in
the table means verified TLS. No login, shipment tracking with customer
data, authenticated API access or transaction was attempted.

| Exact host | Function and official source | Path and measured result |
|---|---|---|
| `api.dalli-service.com` | [Dalli API documentation (Moscow)](https://api.dalli-service.com/doc/v1/) | [`/doc/v1/` · AS3216 200 / AS12389 no HTTP / AS207957 200](https://api.globalping.io/v1/measurements/2tbGk1bQRGvirwQJk00021Us0) |
| `capi.tk-kit.com` | [TK KIT documented client API](https://tk-kit.ru/developers/api) | [`/1.0/geography/email/get-list` · AS3216 401 / AS12389 401 / AS207957 401](https://api.globalping.io/v1/measurements/2ai3R9HQWTETRvzq700021Us0) |
| `dalli-service.com` | [Dalli shipment tracking](https://dalli-service.com/tracking/) | [`/tracking/` · AS3216 200 / AS12389 no HTTP / AS207957 200](https://api.globalping.io/v1/measurements/2WyPpiImHo6xsQ92m00021Urz) |
| `e-kit.pro` | [E-KIT marketplace logistics](https://e-kit.pro/news/akcii/e-kit-oficialnyj-partner-ozon) | [`/news/akcii/e-kit-oficialnyj-partner-ozon` · AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/20yUk2R3lEzcH5UI400021Us0) |
| `khv.aero` | [Khabarovsk Airport flight board](https://khv.aero/online/) | [`/online/` · AS3216 200 / AS12389 200 / AS207957 no HTTP](https://api.globalping.io/v1/measurements/2WUE1TIhrQyZW0T2U00021Ury) |
| `kja.aero` | [Krasnoyarsk Airport apex redirect](https://www.kja.aero/) | [`/` · AS3216 301 / AS12389 301 / AS207957 301](https://api.globalping.io/v1/measurements/26iK76u1bPcnkUM3u00021Ury) |
| `lk.dalli-service.com` | [Dalli Moscow customer login](https://dalli-service.com/clients/) | [`/login.php` · AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2RcemYoZbZ11j0aBw00021Us0) |
| `spblk.dalli-service.com` | [Dalli St Petersburg customer login](https://dalli-service.com/clients/) | [`/login.php` · AS3216 200 / AS12389 no HTTP / AS207957 200](https://api.globalping.io/v1/measurements/2ord2ADnEiuvMTKqs00021Us1) |
| `www.dalli-service.com` | [Dalli www redirect](https://dalli-service.com/support/) | [`/support/` · AS3216 301 / AS12389 no HTTP / AS207957 301](https://api.globalping.io/v1/measurements/2qqwBnsieeFO3OmZ000021Urz) |
| `www.khv.aero` | [Khabarovsk Airport www redirect](https://khv.aero/online/) | [`/online/` · AS3216 301 / AS12389 301 / AS207957 301](https://api.globalping.io/v1/measurements/29xiA16pjgFBFam4200021Us0) |
| `www.kja.aero` | [Krasnoyarsk Airport official site](https://www.kja.aero/) | [`/` · AS3216 200 / AS12389 200 / AS207957 403](https://api.globalping.io/v1/measurements/25uJF318TSCLMUDMU00021Us0) |

The KIT API's documented read endpoint returned the expected Unauthorized
JSON without a token in all three networks. This confirms the API was
reached and authenticated TLS worked, not that an API call succeeded.
Krasnoyarsk's www host returned the official homepage on two networks and
a 403 on the third. Khabarovsk and some Dalli endpoints had no HTTP
response on one of the three networks. These differences are not claims
of nationwide availability or blocking.

Redirects for the www variants of Dalli and Khabarovsk and the
Krasnoyarsk apex were checked together with their destination hosts. The
Vladivostok and Kaliningrad legacy names point at `aerovlad.ru` and
`kgdavia.ru`, respectively. These destinations are already covered by
`domain:ru`; the legacy variants are not included in this batch. The
KIT apex's redirect to `tk-kit.ru` is also not included.

The documented St Petersburg Dalli API host returns an HTTP downgrade
from its HTTPS documentation alias and 500 at the HTTPS target, so it
remains out. Yakutsk's board and Begishevo sales still do not give a
successful page in the sampled checks. The working landing pages
`cdekforward.com` and `cdekglobal.com` were not independently established
as current official CDEK customer-service endpoints. CDEK's documented
`global.cdek.ru` is already covered. Cloud and payment examples
`s3.ru1.storage.beget.cloud`, `s3.timeweb.cloud`, `hb.bizmrg.com`,
`storage.mwsapis.ru`, and `robokassa.com` already match existing rules.

No suffix additions, IP changes, or BLOCK changes.
