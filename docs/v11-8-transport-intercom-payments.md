# GeoSite RU Light v11.8 — transport, intercom and payments

Add five exact `full:` rules to `RU`. No new suffix rules or input sources.

| Exact hostname | Service | First-party evidence |
| --- | --- | --- |
| `flyredwings.com` | Red Wings ticket sales and booking | [Airline website](https://flyredwings.com/) |
| `flysmartavia.com` | Smartavia ticket sales and booking | [Airline website](https://flysmartavia.com/) |
| `payinrussia.com` | Public PayInRussia payment-service site | [Service website](https://payinrussia.com/), [Bank of Russia entry for Promselkhozbank](https://www.cbr.ru/finorg/foinfo/?id=1315037839949) |
| `rdea.rosdomofon.com` | RosDomofon business account login | [Linked from the official website](https://rosdomofon.com/) |
| `rosdomofon.com` | RosDomofon public smart-intercom website | [Official website](https://rosdomofon.com/) |

Candidate sources: the application sections of
[pincetgore/amnezia-app-ru-list](https://github.com/pincetgore/amnezia-app-ru-list/blob/main/config.yaml),
the previously unselected `mvrvntn:whitelist`, and the
[Bank of Russia site register](https://www.cbr.ru/banking_sector/credit/cowebsites/).
These sources provided leads only. No source list was imported. The rules
cover the listed names only. Subdomains such as `app.payinrussia.com`,
`wiki.rosdomofon.com`, and `sip.rosdomofon.com` were not added. This is not
a guarantee that all traffic from these applications will match `RU`.

Compared with v11.7, Light has **3,101 RU rules (+5, −0)** and **18 categories**.
`BLOCK` (43 rules) and all 16 Hydra categories are unchanged.
The DAT is **83,309 bytes**, SHA-256
`3db3e83d90caced77ba9d28bd0462c9983e9de607e0371a3b0a54b5e94afe8bb`.

The local projection with the existing Server policy contains exactly one
`RU` category with **2,989 rules (+5, −0)** and 38 exact names. Its DAT
SHA-256 is `504cde5152b94e029fe990b408063d45818aeb22da3ed68ee5edf477bb922fd8`.
No Server code or policy change is required.
