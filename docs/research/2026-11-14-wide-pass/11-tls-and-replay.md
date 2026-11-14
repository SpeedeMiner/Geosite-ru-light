# Статус TLS и воспроизводимость +245

База зафиксирована на v11.17. Light SHA-256 `75b79f1883e0ae7380621c41bdac89777dc1df660844d141ea98a400526728ec`, Server SHA-256 `d62ce50c0e383bf6a252fd5ed69169bb9de870c9e1ce8821100458118f20ec34`.

На 14:49 UTC+5 с начала часового прохода 48 новых точных правил, из них 47 в первом журнале и ещё Союз биатлонистов России в дополнении. Пары московских HTTP-кодов не удостоверяют цепочку доверия.

| Хост | Наблюдение | Решение |
|---|---|---|
| `satbayev.university` | [HTTP 200/200 из Москвы](https://check-host.net/check-report/57bd39a1k6df) и [200 из AS12389](https://api.globalping.io/v1/measurements/2HHNaGLBB2SoCx8tZ00021VAj). Титул и [контакты](https://satbayev.university/ru/contacts) совпадают. SAN соответствует, но проверка цепочки вернула `UNABLE_TO_VERIFY_LEAF_SIGNATURE`. Выдавший CA — Sectigo, не НУЦ Минцифры. | Не добавлен. TLS перепроверить после исправления цепочки или смены сертификата. |
| `www.akosta.info` | [TLS, SAN и 200](https://api.globalping.io/v1/measurements/2mPLVZXVCNpiG9XM500021VAK). SAN верен, issuer GlobalSign, цепочка не прошла валидацию в трёх сетях. | Не добавлен. Не путать с отсутствием корня НУЦ. |
| `www.carx-tech.com` | [301 и ошибка имени](https://api.globalping.io/v1/measurements/2qnbbo0HQtmk2Rttn00021VAO). Сертификат имеет SAN для `carx-online.com`, а не для адреса запроса. | Старый алиас не добавлен. Цель проверяется отдельно. |
| `www.sharstudio.com` | [Парковка хостинга и ошибка SAN](https://api.globalping.io/v1/measurements/2Iy4YLGd8OSIG5Bnn00021VAQ). | Не добавлен. |
| `www.wizartanimation.com` | [404 и самоподписанный сертификат другого имени](https://api.globalping.io/v1/measurements/2cVaM1sRVDBGWs7M500021VAQ). | Не добавлен. |
| `kazan.aero` | Страница с JS-проверкой вместо первичной страницы. | Не добавлен по HTTP 200. |

Сертификаты [Национального удостоверяющего центра Минцифры](https://nuc.voskhod.ru/) — отдельный сценарий. Для такого сайта следует фиксировать проверку цепочки с официальным корневым сертификатом НУЦ в изолированном trust store, совпадение SAN и проверку ответа из российских сетей. Ошибка цепочки сама по себе не подтверждает ни использование НУЦ, ни блокировку. Глобальное доверие не менять и TLS не отключать.

## Повторить локально

Входы — `geosite_RU.dat` из опубликованных [Light v11.17](https://github.com/SpeedeMiner/Geosite-ru-light/releases/tag/v11.17) и [Server v11.17](https://github.com/SpeedeMiner/Geosite-ru-server/releases/tag/v11.17) и checkout серверного репозитория на `49d7ecae95fbebc21561b5028a4f40d1cf9c8ec7`. Переименуйте два скачанных DAT, чтобы не перепутать их при запуске.

```sh
python3 release-replay.py light-v11.17.dat server-v11.17.dat candidate-245.txt /path/to/Geosite-ru-server replay-245
```

Из штатной сборки и повторной сборки по опубликованным DAT получены побайтово одинаковые файлы:

| Артефакт | RU | SHA-256 |
|---|---:|---|
| Light | 4091 | `0ebcadcbf632f4192c36229c5bbb50b8b8d90310dbccf39c64e5368f2783b45c` |
| Server | 3979 | `3d3a9b0dea18a25afdd88793201942e5076c91d5dd666e4e7824726bfa3bc86a` |

Разница +245 / −0 в обеих сборках, все 44 правила BLOCK и остальные категории Light идентичны, Server содержит только RU. `market.dme.aero` остаётся точным правилом. Для `get-ipv4.com` и `get-ipv6.com` сохранены существующие суффиксные правила. 48 Python-тестов Light, 13 Python-тестов Server и обе Go-цели прошли локально. Это проверка кандидата, а не публикация или GitHub Actions релиз.
