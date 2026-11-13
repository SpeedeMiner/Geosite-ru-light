# GeoSite RU Light v11.11 — verified service companions

Adds 32 exact RU hosts. The 33 P2 entries from the v11.8 gap audit were checked again against v11.10. Of those, 31 were approved, and one additional endpoint was confirmed from a live redirect. No suffix, BLOCK, Hydra or Happ changes.

The selected hosts provide public service pages, portals, service documentation, booking, or vendor-specific resources. Exact rules do not extend to child hostnames. The Ivideon web entries do not imply coverage of its shared CDN or camera streaming.

## Evidence

Public HEAD checks on 2026-11-13 required verified TLS and HTTP 2xx from at least two different Russian ASNs on the listed service path. The Ivideon short link returned an expected 307 to the independently checked login hostname. No accounts, authentication, payments, or application workflows were exercised.

| Exact host | Service and first-party source | Russian probes |
|---|---|---|
| `alrosa.aero` | [АЛРОСА](https://alrosa.aero/) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/25d7pg6KfqYvcYGZ500021Uq0) |
| `assets.weeek.net` | [WEEEK](https://weeek.net/ru/help/workspace/integracii/api) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2fq7HD4gEJGNBYesO00021Uq0) |
| `cdn.flysmartavia.com` | [Smartavia](https://cdn.flysmartavia.com/rules/) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2ZSNElV0M5iwvjg3B00021Uq0) |
| `developers.weeek.net` | [WEEEK](https://developers.weeek.net/api/) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2uytPxstAx8fhhXqM00021Uq0) |
| `docs.yougile.com` | [YouGile](https://docs.yougile.com/docs/admin-guide-linux/api/) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2r4GSCcsuI8DQau2z00021Uq0) |
| `documentation.pruffme.com` | [Pruffme](https://documentation.pruffme.com/) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2YxGbHbRtUTg5IXFK00021Uq0) |
| `dovuz.innopolis.university` | [Университет Иннополис](https://innopolis.university/) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2NDzfHTK3C9xskfv500021Uq0) |
| `edu.innopolis.university` | [Университет Иннополис](https://innopolis.university/) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2DhlvPOiLDCbfZ0TH00021Upz) |
| `go.ivideon.com` | [Ivideon](https://support.ivideon.com/l_rus/knowledge_base/item/180944) | [AS3216 307 / AS12389 307 / AS207957 307](https://api.globalping.io/v1/measurements/2CUVBSfnGaDlt8zYO00021Upz) |
| `help.yougile.com` | [YouGile](https://help.yougile.com/books/baza-znanii-yougile/page/kak-dorabotat-sistemu) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2K0xQfnTPHmNtRvqk00021Uq0) |
| `innopolis.university` | [Университет Иннополис](https://innopolis.university/) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2pMYqd56Xhe6XsoA300021Upz) |
| `lk-dovuz.innopolis.university` | [Университет Иннополис](https://innopolis.university/) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2KBcEIl67l08G1stU00021Uq1) |
| `medpoisk.com` | [Медпоиск](https://medpoisk.com/) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2VX2oIiAeU3mI3rUR00021Upz) |
| `my.ivideon.com` | [Ivideon](https://my.ivideon.com/service/login) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/25VoaX1Iz3RVCRUQb00021Uq1) |
| `pyrus.com` | [Pyrus](https://pyrus.com/ru/help/pyrus-sync/installation-and-system-requirements) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/24rZRO8KPrXinoJ1Q00021Uq0) |
| `rent.unitiki.com` | [Unitiki](https://rent.unitiki.com/) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2IvIZ5hDDYAZMIm5Q00021Uq0) |
| `ru.ivideon.com` | [Ivideon](https://support.ivideon.com/l_rus/knowledge_base/item/180944) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2S9YZOT1jlg9XZO2h00021Upz) |
| `ru.warface.com` | [Warface RU](https://ru.warface.com/news/1011550.html) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2AkIRge4BLqXyzTfQ00021Upz) |
| `rubetek.com` | [Rubetek](https://rubetek.com/rekvizity/) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2ei9pt3qfn5xva29100021Upz) |
| `spark-interfax.com` | [Интерфакс](https://www.interfax.com/) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2IIEs7VYb84avfAv300021Uq0) |
| `support.ivideon.com` | [Ivideon](https://support.ivideon.com/l_rus/knowledge_base/item/180944) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2KtIOkvU0Yifsl0K600021Upz) |
| `support.rubetek.com` | [Rubetek](https://support.rubetek.com/ru/smart-home/) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/225iwsGmNMe1dJMty00021Upz) |
| `support.wirenboard.com` | [Wiren Board](https://support.wirenboard.com/t/ne-obnovlyaetsya-kontroller-wb6/32529) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2DcMqXrOThlaA0snS00021Uq0) |
| `tass.com` | [ТАСС](https://tass.com/today) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2fxp3SRT8Rj7GHkDw00021Uq0) |
| `trassir.com` | [TRASSIR](https://trassir.com/software-updates/manual/setup-cloud40.html) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2q0T84gbpCbUoBGkK00021Uq0) |
| `unitiki.com` | [Unitiki](https://unitiki.com/contacts) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2homMp3axYcepNewm00021Uq0) |
| `weeek.net` | [WEEEK](https://weeek.net/ru/help/workspace/integracii/api) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2RFn5Ddq4pNz0Pwiq00021Uq0) |
| `wiki.rosdomofon.com` | [РосДомофон](https://wiki.rosdomofon.com/ru/%D0%9F%D0%BE%D0%B4%D0%B4%D0%B5%D1%80%D0%B6%D0%BA%D0%B0/%D0%A2%D0%B5%D1%85%D0%BD%D0%B8%D0%BA%D0%B0%D0%BC_%D0%B8_%D0%B0%D0%B4%D0%BC%D0%B8%D0%BD%D0%B8%D1%81%D1%82%D1%80%D0%B0%D1%82%D0%BE%D1%80%D0%B0%D0%BC/IP_%D0%B4%D0%BE%D0%BC%D0%BE%D1%84%D0%BE%D0%BD%D1%8B/%D0%9F%D0%BE%D0%B4%D0%BA%D0%BB%D1%8E%D1%87%D0%B5%D0%BD%D0%B8%D0%B5_IP_%D0%B4%D0%BE%D0%BC%D0%BE%D1%84%D0%BE%D0%BD%D0%B0_%D0%BA_%D0%BE%D0%B1%D0%BB%D0%B0%D0%BA%D1%83_%D0%A0%D0%BE%D1%81%D0%94%D0%BE%D0%BC%D0%BE%D1%84%D0%BE%D0%BD/%D0%9F%D0%BE%D0%B4%D0%BA%D0%BB%D1%8E%D1%87%D0%B5%D0%BD%D0%B8%D0%B5_BasIP) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2WxS7JcoPffVFoT0x00021Uq0) |
| `wiki.wirenboard.com` | [Wiren Board](https://wiki.wirenboard.com/wiki/Bootloader) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2impGZz3Eif1rPSHA00021Uq0) |
| `www.interfax.com` | [Интерфакс](https://www.interfax.com/) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2FUDBSuA0V2SfUP1u00021Uq0) |
| `www.rencapbank.com` | [РенКап Банк](https://www.cbr.ru/finorg/foinfo/?id=1315037838911) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2eXWzUnLwXbJVQwoC00021Upz) |
| `yougile.com` | [YouGile](https://yougile.com/api/) | [AS3216 200 / AS12389 200 / AS207957 200](https://api.globalping.io/v1/measurements/2UxwewCAAMuDI262y00021Uq0) |

## Held out

- `dme.aero`. Public endpoint did not pass TLS validation on any of the three Russian probes. [Measurement](https://api.globalping.io/v1/measurements/2Vf8FdtGoY7nIU1Vb00021Uq0).
- `ddxfitness.me`. Public site returned HTTP 200, but its connection to the production application or service workflow is not established. [Measurement](https://api.globalping.io/v1/measurements/2tm8NHzbYYjaSBvVJ00021Uq0).

The earlier holds for the PayInRussia app, the Domodedovo www host and the SIP endpoint remain in effect. This change does not route telemetry or CDN suffixes.

## Build results

- Light: 3,163 RU rules (+32, −0), 44 unchanged BLOCK rules and 18 categories. DAT SHA-256: `213b088ba0be5f9fe9c38534a7fc7782ee7f10c1e23e0b729e01b58556a860d3`.
- Server projection: 3,051 RU rules (+32, −0) in one category. DAT SHA-256: `3bbbf78dcc3b6da6ee2723b9882003081f0a6ac34fde5c8b52e653fd5314b45a`.
