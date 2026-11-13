# GeoSite RU Light v11.9 — verified service hosts from Russian networks

The 21 high-priority names in the v11.8 coverage audit were rechecked. Of those, 17 qualify, and two more are required for the confirmed TRASSIR sign-in redirects. The candidate adds 19 exact RU rules without changing source inputs or suffix policy.

## Method

On 2026-11-13, public Globalping probes from Russian networks AS12389 (Rostelecom), AS3216 (Vimpelcom) and AS207957 (SERV.HOST GROUP) requested the listed public HTTPS paths. An exact rule requires a first-party service reference or a verified redirect from one, and successful responses with verified TLS from at least two distinct Russian ASNs. For the TRASSIR chain, every included hop separately met that threshold. Timeouts are not treated as nationwide blocks.

This verifies public endpoints, not payment, account authentication, SIP sessions or other authenticated workflows. The APK was checked with HEAD without downloading the file. A third-party measurement ID links to each public check, and the key results are recorded here independently of its retention.

## Approved

| Exact hostname | Service | Public path and successful Russian responses | Evidence |
|---|---|---|---|
| `api.pyrus.com` | Pyrus | HEAD `/` — AS3216 202 / AS12389 202 / AS207957 202 | [Service](https://pyrus.com/ru/help/pyrus-sync/installation-and-system-requirements), [measurement](https://api.globalping.io/v1/measurements/28VTUP8hHVkTItKrW00021Uoy) |
| `app.weeek.net` | WEEEK | HEAD `/` — AS3216 200 / AS12389 200 / AS207957 200 | [Service](https://weeek.net/ru/help/workspace/integracii/api), [measurement](https://api.globalping.io/v1/measurements/2RlysmVIaCxaXd47x00021Uoy) |
| `apply.innopolis.university` | Университет Иннополис | HEAD `/` — AS3216 200 / AS12389 200 / AS207957 200 | [Service](https://apply.innopolis.university/), [measurement](https://api.globalping.io/v1/measurements/2zNwurdylwYRdavNB00021Uoy) |
| `cdek.digital` | СДЭК Диджитал | HEAD `/integration` — AS3216 200 / AS12389 200 / AS207957 200 | [Service](https://cdek.digital/integration), [measurement](https://api.globalping.io/v1/measurements/2t67NTS6R1JVk2rxO00021Uoy) |
| `check-in.flysmartavia.com` | Smartavia | HEAD `/check-in/` — AS3216 200 / AS12389 200 / AS207957 200 | [Service](https://cdn.flysmartavia.com/rules/), [measurement](https://api.globalping.io/v1/measurements/2c1JR7aVPs8NU45EN00021Uoy) |
| `cloud.trassir.com` | TRASSIR | HEAD `/` — AS3216 307 / AS12389 307 / AS207957 307 | [Service](https://trassir.com/software-updates/manual/setup-cloud40.html), [measurement](https://api.globalping.io/v1/measurements/24bFJg68Ieh0UjvKU00021Uoy) |
| `download.payinrussia.com` | PayInRussia | HEAD `/payrus-latest.apk` — AS3216 200 / AS12389 200 / AS207957 200 | [Service](https://new.payinrussia.com/ru/install/), [measurement](https://api.globalping.io/v1/measurements/2m9xlzBSYJKmIoF4300021Uoy) |
| `fw-releases.wirenboard.com` | Wiren Board | HEAD `/` — AS3216 200 / AS207957 200 | [Service](https://wiki.wirenboard.com/wiki/Bootloader), [measurement](https://api.globalping.io/v1/measurements/2zgfgFqtAENDB1YKg00021Uoy) |
| `nbc.aero` | Бегишево | HEAD `/` — AS3216 200 / AS12389 200 / AS207957 200 | [Service](https://nbc.aero/), [measurement](https://api.globalping.io/v1/measurements/2lCHmxFxQ7hXd2s0D00021Uoy) |
| `pruffme.com` | Pruffme | HEAD `/` — AS3216 200 / AS207957 200 | [Service](https://pruffme.com/landing/u252863/tmp1562659751), [measurement](https://api.globalping.io/v1/measurements/2ojkftvKUWOIajCXP00021Uoy) |
| `ref.flysmartavia.com` | Smartavia | HEAD `/online/reference/modification/` — AS3216 200 / AS207957 200 | [Service](https://ref.flysmartavia.com/online/reference/modification/), [measurement](https://api.globalping.io/v1/measurements/2UOn2lBDiBqmS1vwz00021Uoy) |
| `ru.cloud.trassir.com` | TRASSIR | HEAD `/user-login` — AS3216 301 / AS12389 301 / AS207957 301 | [Service](https://news.ru.cloud.trassir.com/uploads/TrassirCloud_ru.pdf), [measurement](https://api.globalping.io/v1/measurements/2LkhhvGF8c4QwiVfw00021Uoz) |
| `ru.yougile.com` | YouGile | HEAD `/api-v2` — AS3216 200 / AS12389 200 / AS207957 200 | [Service](https://ru.yougile.com/api-v2), [measurement](https://api.globalping.io/v1/measurements/2vI35bfsZJ80TmbGa00021Uoy) |
| `s3.regru.cloud` | Рег.облако | HEAD `/` — AS3216 200 / AS207957 200 | [Service](https://img.reg.ru/faq/poryadok_predostavleniya_servisa-obyektnoe_hranilishche_s3_20012026-1.pdf), [measurement](https://api.globalping.io/v1/measurements/20wxkDwW41INy6dvS00021Uoy) |
| `sdo.mpgu.org` | МПГУ | HEAD `/sign-up/request` — AS3216 200 / AS12389 200 / AS207957 200 | [Service](https://mpgu.su/anonsyi/proektov-metodike-prepodavanija-izobrazitelnogo-iskusstva/), [measurement](https://api.globalping.io/v1/measurements/2UNtBEKDG523Insnb00021Uoy) |
| `sigma.cloud.trassir.com` | TRASSIR | HEAD `/user-login` — AS3216 200 / AS12389 200 / AS207957 200 | [Service](https://trassir.com/software-updates/manual/setup-cloud40.html), [measurement](https://api.globalping.io/v1/measurements/2JFBiQVDlilb6Snnf00021Uoz) |
| `telemedicine.medpoisk.com` | Медпоиск / СберЗдоровье | HEAD `/` — AS3216 200 / AS207957 200 | [Service](https://telemedicine.medpoisk.com/), [measurement](https://api.globalping.io/v1/measurements/2GjgHEAkP45RWtvZn00021Uoy) |
| `www.alrosa.aero` | АЛРОСА | HEAD `/` — AS3216 200 / AS12389 200 / AS207957 200 | [Service](https://www.alrosa.aero/news/autumn-winter-2026), [measurement](https://api.globalping.io/v1/measurements/2kcaFwtTLIJxz68By00021Uoy) |
| `www.rusline.aero` | РусЛайн | HEAD `/read/check-in/` — AS3216 200 / AS12389 200 / AS207957 200 | [Service](https://www.rusline.aero/read/check-in/), [measurement](https://api.globalping.io/v1/measurements/2PgUue6tfvBbxsDHl00021Uoy) |

TRASSIR sign-in: https://cloud.trassir.com → https://ru.cloud.trassir.com → https://sigma.cloud.trassir.com. No wildcard for the vendor cloud.

## Held out

| Host | Why it is not included | Measurement |
|---|---|---|
| `app.payinrussia.com` | HTTP 200, but TLS verification failed on all checked probes, twice | [Measurement](https://api.globalping.io/v1/measurements/2Z7b9cJE5nCEpGToq00021Uoz) |
| `new.payinrussia.com` | HTTPS homepage returns 200, but the documented /ru/install/ returned 404 on both HEAD and GET | [Measurement](https://api.globalping.io/v1/measurements/223B8ujfZwCPM8UCy00021Uoy) |
| `sip.rosdomofon.com` | Three matching A responses only, with no check of a working SIP session | [Measurement](https://api.globalping.io/v1/measurements/2myX7zCy8BZtyJsNz00021Uoy) |
| `www.dme.aero` | HTTP responses had unverified TLS, with additional handshake timeouts | [Measurement](https://api.globalping.io/v1/measurements/26Pcfw9NLCbTm4e0o00021Uox) |

## Exact BLOCK addition

`full:crashlyticsreports-pa.googleapis.com` is the only BLOCK change. The
[Firebase SDK project](https://github.com/firebase/firebase-android-sdk/issues/4474)
identifies this hostname as a crash-report upload endpoint.
[Firebase documentation](https://firebase.google.com/docs/android/play-data-disclosure#crashlytics)
describes stack traces, relevant application state and device metadata.
The Google APIs apex, sibling names and descendants of this host are not
added to BLOCK by this rule. The Server DAT intentionally exports only RU.

## Build results

Light contains **3,120 RU rules (+19, −0)** and 18 categories. BLOCK contains 44 rules (+1, −0). The 16 other categories are unchanged. Its DAT is 83,799 bytes, SHA-256 `cf728ca7f6620fd12460f29e9f8d541e93eeb754276368e095f0ef6ec22410cc`.
The existing Server projection contains **3,008 RU rules (+19, −0)** in its single RU category. Its DAT is 54,367 bytes, SHA-256 `843b041c6baa137aeeb5eecc8f6fca811f002c32c5008d9581b3169f98c7238d`. No Server policy change is needed.

Offline replay reproduced all five candidate assets. The five pinned v11.8 rollback assets were verified independently. Python and Go suites passed.
