# Domodedovo procurement portal — exact RU rule

The [first-party portal](https://market.dme.aero/) identifies itself as
Domodedovo Airport's electronic procurement platform. It has a public
[rules page](https://market.dme.aero/rules.aspx). Its role is independently
corroborated by [HSE's procurement platform registry](https://www.hse.ru/data/2024/10/23/1942013191/%D0%BD%D0%BE%D0%B2%D1%8B%D0%B9%20%D0%BF%D0%B5%D1%80%D0%B5%D1%87%D0%B5%D0%BD%D1%8C%20%D0%AD%D0%A2%D0%9F-%D0%BE%D0%BA%D1%82%D1%8F%D0%B1%D1%80%D1%8C%202024.pdf).

On 2026-11-13 AS12389 (Rostelecom), AS3216 (Vimpelcom) and AS207957
(SERV.HOST GROUP) each returned HTTP 200 and verified TLS for
[HEAD /](https://api.globalping.io/v1/measurements/2Odk4GgekFmc8nQal00021UqF)
and [GET /rules.aspx](https://api.globalping.io/v1/measurements/2vWrXL0IEwGwOQCTT00021UqG).
On both paths the observed leaf was issued by GlobalSign and its DNS SAN
`*.dme.aero` covered the market host. The apex and www probes presented a
different leaf for `dme.ru`. These are anonymous public requests. No login or procurement transaction
was exercised.

The published v11.11 Light DAT did not cover this hostname in RU or BLOCK.
Add only `full:market.dme.aero` to RU. `business.dme.ru` also
[passed checks](https://api.globalping.io/v1/measurements/2zq4Z63bUFUE0oqZ900021UqG)
and already matches `domain:ru`. The distinct `dme.aero` and `www.dme.aero`
hosts remain on HOLD because the [apex](https://api.globalping.io/v1/measurements/2Vf8FdtGoY7nIU1Vb00021Uq0)
and [www](https://api.globalping.io/v1/measurements/2Q6AN3zZ4iUN3wlyI00021Uq0)
presented a certificate that did not cover their names. No wildcard
for `.aero` or `dme.aero` and no BLOCK change.
