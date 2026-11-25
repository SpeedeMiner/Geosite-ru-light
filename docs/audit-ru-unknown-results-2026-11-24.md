# Доработка проверки UNKNOWN FQDN — 24 ноября 2026

[Полный архив: списки категорий, таблица для 4 495 имён и доказательства](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/45454309967/artifacts/14949532293) · [Проверка 33 кандидатов](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/45452539903) · [Проверенные источники](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/45452784126) · [Сравнение РФ и США](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/45453796025).

| Категория | Имена | Доля |
|---|---:|---:|
| ALIVE | 2 694 | 59,93% |
| INFRASTRUCTURE | 4 | 0,09% |
| GEO_BLOCKED | 0 | 0% |
| PARKED | 0 | 0% |
| EXPIRED | 0 | 0% |
| DEAD | 28 | 0,62% |
| UNKNOWN | 1 769 | 39,35% |

Здесь DEAD означает **отсутствие регистрации и публичного делегирования на момент измерения**, а не доказанный срок истечения или историю домена. С нулём в прочих категориях подтверждённые случаи не выявлены; их отсутствие этим не доказано. Историческая аттестация VPN ограничена отсутствием независимых сохранённых исходных ответов и пакетных трасс.

Четыре API-узла в INFRASTRUCTURE — `api-eu.mixpanel.com`, `api-in.mixpanel.com`, `api.networktools.dev`, `api.onesignal.com`. Они вернули JSON с признаками API через TLS с проверенным именем; проверка выполнена из GitHub runner и сама по себе не устанавливает доступность из России. Запросы 401/403/404 не объявлялись признаком смерти сервиса.

## 28 подтверждённых кандидатов на рассмотрение исключения

Для каждого: родительская авторитетная зона вернула NXDOMAIN; RDAP реестра — 404; WHOIS реестра явно сообщил об отсутствии или доступности для регистрации. Это согласованные фактические признаки отсутствия регистрации в момент проверки. Перед исключением нужно повторно сверить состояние и учесть, что домен может быть зарегистрирован заново, а внешние источники могут вернуть правило при следующей сборке. Ни одно правило не изменено. Совпадение в закреплённом источнике показывает наличие записи в проверенном снимке, но не всегда доказывает, что именно он внёс правило в конкретный исторический релиз.

| Правило | Доказательства | Совпадения в источниках |
|---|---|---|
| `domain:aksyuterian.com` | e.gtld-servers.net,d.gtld-servers.net; RDAP 404; whois.verisign-grs.com: No match for "AKSYUTERIAN.COM". | davoyan |
| `domain:aodahl.com` | e.gtld-servers.net,d.gtld-servers.net; RDAP 404; whois.verisign-grs.com: No match for "AODAHL.COM". | runetfreedom, yularzhi, digne |
| `domain:avito-services.com` | e.gtld-servers.net,d.gtld-servers.net; RDAP 404; whois.verisign-grs.com: No match for "AVITO-SERVICES.COM". | grimbird |
| `domain:bluestacksads.com` | e.gtld-servers.net,d.gtld-servers.net; RDAP 404; whois.verisign-grs.com: No match for "BLUESTACKSADS.COM". | yularzhi |
| `domain:bluestacksapi.com` | e.gtld-servers.net,d.gtld-servers.net; RDAP 404; whois.verisign-grs.com: No match for "BLUESTACKSAPI.COM". | yularzhi |
| `domain:bluestackscdn.com` | g.gtld-servers.net,h.gtld-servers.net; RDAP 404; whois.verisign-grs.com: No match for "BLUESTACKSCDN.COM". | yularzhi |
| `domain:bluestackscloud.com` | d.gtld-servers.net,c.gtld-servers.net; RDAP 404; whois.verisign-grs.com: No match for "BLUESTACKSCLOUD.COM". | yularzhi |
| `domain:bluestacksdata.com` | b.gtld-servers.net,i.gtld-servers.net; RDAP 404; whois.verisign-grs.com: No match for "BLUESTACKSDATA.COM". | yularzhi |
| `domain:bluestacksengine.com` | c.gtld-servers.net,k.gtld-servers.net; RDAP 404; whois.verisign-grs.com: No match for "BLUESTACKSENGINE.COM". | yularzhi |
| `domain:cdn-tinkoff.com` | b.gtld-servers.net,m.gtld-servers.net; RDAP 404; whois.verisign-grs.com: No match for "CDN-TINKOFF.COM". | local/ru.txt |
| `domain:honestmark.org` | v0n0.pir-ns.org,v0n2.pir-ns.org; RDAP 404; whois.publicinterestregistry.org: Domain not found. | grimbird |
| `domain:investalfabank.com` | d.gtld-servers.net,a.gtld-servers.net; RDAP 404; whois.verisign-grs.com: No match for "INVESTALFABANK.COM". | hydra, mvrvntn, vpnyasha |
| `domain:lead-pro2023.online` | ns10.trs-dns.org,ns01.trs-dns.net; RDAP 404; whois.nic.online: >>> Domain lead-pro2023.online is available for registration | hydra, mvrvntn, vpnyasha |
| `domain:rosbank-credit.com` | e.gtld-servers.net,g.gtld-servers.net; RDAP 404; whois.verisign-grs.com: No match for "ROSBANK-CREDIT.COM". | runetfreedom, yularzhi, digne |
| `domain:russieactuelle.fr` | g.ext.nic.fr,d.nic.fr; RDAP 404; whois.nic.fr: %% NOT FOUND | runetfreedom, yularzhi, digne |
| `domain:sberfinance.net` | d.gtld-servers.net,f.gtld-servers.net; RDAP 404; whois.verisign-grs.com: No match for "SBERFINANCE.NET". | davoyan |
| `domain:sbruss.store` | ns10.trs-dns.org,ns10.trs-dns.info; RDAP 404; whois.nic.store: >>> Domain sbruss.store is available for registration | davoyan |
| `domain:smsemailstats.com` | g.gtld-servers.net,b.gtld-servers.net; RDAP 404; whois.verisign-grs.com: No match for "SMSEMAILSTATS.COM". | davoyan |
| `domain:tbankjob.site` | ns10.trs-dns.info,ns01.trs-dns.com; RDAP 404; whois.nic.site: >>> Domain tbankjob.site is available for registration | davoyan |
| `domain:tinkoff-anketa.site` | ns01.trs-dns.com,ns10.trs-dns.info; RDAP 404; whois.nic.site: >>> Domain tinkoff-anketa.site is available for registration | davoyan |
| `domain:tinkoff-digital.com` | b.gtld-servers.net,l.gtld-servers.net; RDAP 404; whois.verisign-grs.com: No match for "TINKOFF-DIGITAL.COM". | davoyan |
| `domain:tinkoffdigital.com` | m.gtld-servers.net,k.gtld-servers.net; RDAP 404; whois.verisign-grs.com: No match for "TINKOFFDIGITAL.COM". | davoyan |
| `domain:tinkoffip.site` | ns01.trs-dns.com,ns10.trs-dns.info; RDAP 404; whois.nic.site: >>> Domain tinkoffip.site is available for registration | davoyan |
| `domain:tinkoffreg.site` | ns01.trs-dns.com,ns01.trs-dns.net; RDAP 404; whois.nic.site: >>> Domain tinkoffreg.site is available for registration | davoyan |
| `domain:tynkoff.cc` | ac2.nstld.com,ac3.nstld.com; RDAP 404; ccwhois.verisign-grs.com: No match for "TYNKOFF.CC". | davoyan |
| `domain:vk.cloud` | ns01.trs-dns.net,ns10.trs-dns.org; RDAP 404; whois.nic.cloud: >>> Domain vk.cloud is available for registration | mvrvntn |
| `domain:vkcache.com` | e.gtld-servers.net,b.gtld-servers.net; RDAP 404; whois.verisign-grs.com: No match for "VKCACHE.COM". | runetfreedom, hydra, grimbird, mvrvntn, yularzhi, vpnyasha, digne |
| `domain:vkusvill.net` | c.gtld-servers.net,b.gtld-servers.net; RDAP 404; whois.verisign-grs.com: No match for "VKUSVILL.NET". | mvrvntn |

Из первоначальных 33 в этот список не попали `bankonline.center`, `bonus-card.ml`, `creditdevelopment.pro`, `rtde.express`, `russiatoday.tv`: в доступном WHOIS отсутствовало однозначное подтверждение, хотя DNS и RDAP дали отрицательные ответы. Они остаются UNKNOWN.

## Сетевые данные и сравнение

В исходных 1 801 UNKNOWN: 1 424 имели хотя бы один HTTP-ответ; 17 — ошибку TLS без HTTP-ответа; 74 — NXDOMAIN в двух конфигурациях DNS; 122 — DNS-адрес без HTTP-ответа; 164 — неопределённый DNS. Это взаимоисключающие технические группы по приоритету, а не выводы о назначении или работоспособности каждого сервиса; данные групп относятся к состоянию до перевода 32 имён в DEAD/INFRASTRUCTURE.

Для десяти спорных имён повторён одинаковый HTTPS GET с одинаковым User-Agent из двух проверенных российских ASN и точки США. У шести в российском ответе обнаружен признак WAF/CAPTCHA; по остальным 403 не позволяет достоверно отличить географическое ограничение от фильтрации по IP или иной политики. Подтверждённых GEO_BLOCKED нет; отдельные результаты и причины — `geo-matched-summary.csv` в архиве.

Для 458 регистрационных доменов с неполными сведениями выполнен адресный WHOIS/RDAP follow-up с группировкой по доменам и ограничением запросов; 73 повторных RDAP-запроса вернули запись. По части зон IANA WHOIS referral отсутствовал, по некоторым получены таймауты или ограничения. Для каждого оставшегося UNKNOWN последняя доступная причина приведена в `classification.csv`. Домен-суперзона `domain:` покрывает поддомены; проверка корня не устанавливает судьбу каждого из них.

Все результаты предназначены для рассмотрения в Draft PR №46. Main, правила, релизы и CDN не изменялись.
