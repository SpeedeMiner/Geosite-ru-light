# GeoSite RU v11.13 — Russian airports and logistics

Add eleven exact RU hostnames not covered by v11.12.

- Khabarovsk and Krasnoyarsk airports: `khv.aero`, `www.khv.aero`, `kja.aero`, `www.kja.aero`.
- Dalli tracking, sign-in and public Moscow API documentation: `dalli-service.com`, `www.dalli-service.com`, `lk.dalli-service.com`, `spblk.dalli-service.com`, `api.dalli-service.com`.
- TK KIT client API and E-KIT logistics: `capi.tk-kit.com`, `e-kit.pro`.

Each hostname had verified HTTPS from at least two Russian networks.
The KIT API returned its expected unauthenticated 401. No credentials
or transactions were used. See [measurements and exclusions](ru-airports-and-logistics-20261113.md).

Light: 3,184 RU rules (+11, −0), 44 unchanged BLOCK rules and no changes to
the other categories. Server projection: 3,072 rules (+11, −0) in the
single RU category. GeoIP and external source pins are unchanged.
The rollback baseline is v11.12.
