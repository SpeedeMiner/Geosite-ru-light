# Russian aviation follow-up after GeoSite v11.13

Compared against published v11.13 Light RU and BLOCK and Server RU.
None of the four proposed names match an existing rule in those categories.
Use exact names only. Measurements were anonymous HTTPS GETs from AS12389,
AS3216 and AS207957 in that order. HTTP statuses in the table were counted
only when TLS authentication and hostname checks succeeded.

| Exact host | Role and source | Probe path and HTTP result |
|---|---|---|
| `northwest.aero` | [Business aviation operator homepage](https://ar-kuf.ru/contacts/companies/) | [`/` · 200 / 200 / 200](https://api.globalping.io/v1/measurements/21Hn4IYbvXbTctr1U00021Usc) |
| `www.northwest.aero` | [Business aviation operator homepage](https://www.northwest.aero/company/contacts/) | [`/` · TLS timeout / 200 / 200](https://api.globalping.io/v1/measurements/2oI4PGXV7X7ZXiazY00021Usc) |
| `www.flyredwings.com` | [HTTPS redirect to Red Wings check-in](https://flyredwings.com/check-in/) | [`/check-in/` · 301 / 301 / 301](https://api.globalping.io/v1/measurements/2ciG0kzbVtbdQLboN00021Use) |
| `www.flysmartavia.com` | [HTTPS redirect to Smartavia homepage](https://flysmartavia.com/) | [`/` · 301 / 301 / 301](https://api.globalping.io/v1/measurements/2zkDgzycmGBbsopsZ00021Use) |

The two airline redirects preserve HTTPS and land on the already-covered
canonical host. Both destinations returned verified HTTP 200 on all three
probes ([Red Wings](https://api.globalping.io/v1/measurements/2GA3AIldjNjd6reqB00021Use),
[Smartavia](https://api.globalping.io/v1/measurements/2MVXeVtJ3JhQxb08p00021Use)).
These are host rules, not URL path rules.

## Rechecked and excluded

- [`market.dme.aero`](https://api.globalping.io/v1/measurements/2NmJJpliUz8N3kxEv00021Usc) already matches
  an exact RU rule and returned verified TLS and HTTP 200 on all three probes.
  [`dme.aero`](https://api.globalping.io/v1/measurements/2ENUIhdZrAv40p2af00021Usc) and
  [`www.dme.aero`](https://api.globalping.io/v1/measurements/2SdULvyRBnXRK4XT300021Usc) presented a GlobalSign
  certificate covering `dme.ru` and its listed names, not `dme.aero`.
  Where HTTP was reported, TLS had `ERR_TLS_CERT_ALTNAME_INVALID`.
  This is a hostname mismatch, not a missing Russian trust anchor.
- [`yks.aero` flight board](https://api.globalping.io/v1/measurements/2MvJL9a5H1OOd4M5X00021Usc) returned
  verified TLS and HTTP 403 on all three probes.
  [`www.yks.aero`](https://api.globalping.io/v1/measurements/29y9oBRLmVIqUdrdO00021Usc) returned
  TLS `unrecognized_name` on all three. This does not establish
  nationwide blocking or an unavailable origin.
- [`pkc.aero`](https://api.globalping.io/v1/measurements/2obmJGrUusNBosMuK00021Usc) and
  [`www.pkc.aero`](https://api.globalping.io/v1/measurements/2PQ7Qdy5lUjVA0h5O00021Usd) are legacy HTTPS
  redirects to `ar-pkc.ru`, already covered by the RU suffix.
- The reviewed Surgut and Yuzhno-Sakhalinsk airport sites, Baikal Service,
  Delovye Linii and EDO.Potok endpoints already match the RU suffix.
  CDEK Kazakhstan matches the existing KZ suffix.

No changes to BLOCK, GeoIP or external sources.
