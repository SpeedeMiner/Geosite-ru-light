# Итоговый пересчёт актуальности RU — 24 ноября 2026

[Полный архив: классификация, списки и доказательства](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/45456957539/artifacts/14951725470) · [повторная проверка 33](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/45456043247) · [дополнительный WHOIS пяти имён](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/45456266146) · [предыдущая проверка источников](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/45452784126).

Исходный DAT: SHA-256 `027939e3a31591bd48a57428c893a8237fe61352d90a8c3077b39366a3a3d0cc`. Использованы сохранённые 14 350 наблюдений и результаты последующих адресных проверок. Новый полный VPN-аудит не выполнялся.

## Результат для 4 495 уникальных FQDN

| Классификация | Количество | Доля |
|---|---:|---:|
| Содержимое подтверждено из РФ | 2 248 | 50,01% |
| HTTPS-сервер отвечает; содержимое из РФ не подтверждено | 1 611 | 35,84% |
| Действующая инфраструктура | 4 | 0,09% |
| Подтверждённая геоблокировка | 0 | 0% |
| На момент проверки не зарегистрирован и не делегирован | 29 | 0,65% |
| Недостаточно данных | 603 | 13,41% |

Категории взаимоисключающие. К отдельным перекрывающимся показателям относятся **3 798 имён с хотя бы одним HTTPS-ответом с валидным TLS из российской точки** и **1 589 — из точки США**; эти числа не складываются. Российское содержимое считалось подтверждённым только при записи проверенного TLS и непустого 2xx по исходному классификатору. Отвечающий сервер, в том числе с 401, 403, 404 или перенаправлением, подтверждает сетевой ответ конечной точки, но может быть WAF, прокси или заглушкой и не доказывает, что нужный сервис доступен. Действующая инфраструктура представлена четырьмя API, отдельно подтверждёнными по TLS и JSON из GitHub runner; доступность их содержимого из РФ этим не установлена.

Ранее 446 переходов с корректным HTTPS и итоговым 2xx относились к ALIVE; теперь они включены в категорию отвечающих серверов, поскольку прежний код не проверял содержательность тела после перенаправления. VPN-выходы в исторических наблюдениях основаны на сохранённых атрибутах самого инструмента; независимые исходные ответы и пакетные трассы не сохранились. Отсутствие подтверждённой геоблокировки не доказывает, что её нет.

Из 603 неопределённых: для 393 есть DNS-адреса; 45 получили NXDOMAIN в двух конфигурациях DNS; у 14 зафиксирован DNS timeout; у 10 — отказ/ошибка DNS-серверов; у 141 — другие результаты или NODATA. Это не равнозначно недоступности приложения. Для каждого имени исходные результаты DNS, регистрации и ошибки доступны в `classification.csv` и `classification.json` архива. В десяти адресных сравнениях РФ/США признаки WAF/CAPTCHA встречены у шести; 403/200 без явных географических признаков не квалифицируются как подтверждённая геоблокировка.

## Рекомендованные к рассмотрению 29 исключений

У каждого правила повторно получены авторитетный NXDOMAIN, RDAP 404 и явный отрицательный ответ WHOIS реестра. Это подтверждает **текущее отсутствие регистрации**, но не дату истечения и не невозможность будущей регистрации. Перед изменением правил нужно ещё раз проверить состояние домена; возвращение через источники и будущая перерегистрация остаются возможными. Таблица — рекомендация для отдельного изменения, а не выполненное исключение. Совпадения с закреплёнными источниками не доказывают, какой именно источник включил правило в исторический релиз.

| Правило | Доказательства | Совпадения в проверенных источниках |
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
| `domain:bonus-card.ml` | Авторитетная зона: NXDOMAIN; RDAP 404; whois.nic.ml: объект не существует | davoyan |
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

Для `bankonline.center`, `creditdevelopment.pro`, `rtde.express` и `russiatoday.tv` повторно получены отрицательные DNS/RDAP-данные, но дополнительный WHOIS не дал достаточно однозначного отрицательного ответа. Они не включены в рекомендации и остаются неопределёнными.

## Существующая защита от повторного импорта

В [build.go](https://github.com/SpeedeMiner/Geosite-ru-light/blob/audit/ru-domain-liveness/tools/ru-geosite-filter/build.go) `forbiddenSubtreeInRU` проверяет запрещённые корни, их поддомены и покрывающие их `RootDomain`; сейчас она явно содержит `4pda.to` и `habr.com`. Она вызывается при добавлении позитивных источников и при финальной проверке сформированной категории RU. [validate.go](https://github.com/SpeedeMiner/Geosite-ru-light/blob/audit/ru-domain-liveness/tools/ru-geosite-filter/validate.go) повторно проверяет эту политику. Это существующий механизм, который может блокировать повторный импорт из внешних источников.

Отдельная карта `excludedRUPositiveDomains` в `addRoot` ограничена точными именами и не является полноценным запретом поддерева и покрывающих суффиксов. Простое удаление строки из `local/ru.txt` не исключает повторного внесения внешними источниками. Например, `cdn-tinkoff.com` присутствует также в `data/v11-approved-effective-ru.txt`; при дальнейшем изменении необходимо согласовать approved-манифест и семантический контроль потерь относительно релиза. Ни код политики, ни правила, ни манифест в этом аудите не менялись.

PR №46 остаётся Draft. Обновление исключений, публикация релиза и обновление CDN не выполнялись.
