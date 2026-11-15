# Публичные продуктовые домены МТС и региональных операторов

Отсчёт от v11.19 Light и Server и от предыдущей очереди +72. Проверки растут от первичных ссылок, не от перебора поддоменов. В каталогах отдельно отмечаются внешние ссылки, примеры и встраиваемые ресурсы. DNS, наблюдаемый BGP origin, организационная связь и пригодность для DIRECT учитываются раздельно.

| Направление | Основные источники |
| --- | --- |
| TeamStream, VDome и Exolve | [TeamStream](https://mws.ru/docs/docum/s55.html), [встраивание](https://support.mts.ru/mws_teamstream/kod-vstavki-videopleera/kak-razmestit-kod-vstavki), [VDome](https://domofon.mts.ru/eula.html), [Exolve](https://docs.exolve.ru/docs/ru/api-reference/sms-api/). [Квитанции источников](source-receipts-business-01.tsv). |
| Ticketscloud | [Каталог МТС Live](https://b2b-live.mts.ru/ticket-services), [условия покупки](https://ticketscloud.com/static/docs/customer_rule.pdf), [API v2](https://doc.ticketscloud.org/ru/latest/walkthrough/basics.html). [Сетевые наблюдения](vpn-43736677600-ticketing.tsv). |
| «Зелёная точка» | [Пресс-релиз МТС](https://moskva.mts.ru/about/media-centr/soobshheniya-kompanii/novosti-mts-v-rossii-i-mire/2023-05-02/mts-zavershila-pokupku-regionalnyh-operatorov-fiksirovannoj-svyazi-gk-zelyonaya-tochka), [старое меню Тамбова](https://tambov.zelenaya.net/contacts/), [официальный ребрендинг](https://zelenaya-net.ru/news/zelenaya-tochka-teper-mts-home). [План](greenpoint-plan.tsv). |

Первые два подтверждённых точных имени — кабинет зрителя Ticketscloud и справка на явном пути. У корня справки отдельный переход на Read the Docs, который не подтвердился. Это не основание включать платформу, общий CDN или тестовую среду. [Очередь +74](stacked-seventy-four.txt) · [replay](full-build-replay-seventy-four.tsv).

| Направление | Решение по итогам проверки |
| --- | --- |
| «Зелёная точка» | 16 точных имён, включая кабинет Тамбова. Два спорных города не добавлены. [Первый прогон](vpn-43736945426-greenpoint.tsv), [оставшиеся города](vpn-43737375054-green-cities.tsv). |
| Seven Sky | 5 точных имён отдельного оператора. Вход, ТВ и домофон не тестировались после публичной страницы. Магазин исключён из-за повторяющегося 307. [Прогон](vpn-43737267639-seven-sky.tsv) и [оферта](https://tv.seven-sky.net/eula). |
| Билайн | 1 точный адрес партнёрского продукта. В официальной оферте указан `beeline.suvvy.ai`. В обеих российских сетях получен TLS/200 с заголовком Beeline AI. Правило не распространяется на платформу Suvvy. [Оферта](https://static.beeline.ru/upload/images/Documents/17263-idp-argeement.html) и [прогон](vpn-43737685006-operator-followup.tsv). |

На DNS-срезе 46 пар хост/IP, из них 38 покрыты закреплённым GeoIP RU. Восемь строк за пределами GeoIP — по четыре адреса Cloudflare для `doc.ticketscloud.org` и `ticketscloud.readthedocs.io`, набор адресов у обоих совпадает. Это основание различать два имени на уровне GeoSite, не выводить новый подсетевой маршрут. RIS местами вернул NA, в таблицах сохранены исходные пропуски даже при наличии успешного ответа с тем же IP в другом временном срезе. [Сопоставление GeoIP](geoip-crosscheck.tsv).

Волна добавляет 25 правил к предыдущим 72. [Очередь +97](stacked-ninety-seven.txt) · [повторная сборка](full-build-replay-ninety-seven.tsv). Все правки остаются в research-ветке.

### Проверка покрытия по каталогам

Пять тематических выборок дали 303 пары «источник — хост». Из 69 запросов к источникам 47 дали HTML/200 со строгим TLS, не каждый такой ответ пригоден как каталог. На странице части материалов T2 рабочая среда не дала пригодный HTML, использовали также опубликованные условия и ссылку на Wink. МТС Медиа уже работает как ON Медиа, её текущие продуктовые и правовые страницы не дали новых непокрытых собственных имён кроме независимо рассмотренных билетных сервисов. Из упомянутых площадок загрузки и промо не делаем новых правил. [Отчёт МТС](https://ar2025.mts.ru/mts-segodnya/gruppa-mts-v-2025-godu/) · [структура ON Медиа](https://on-media.ru/about) · [релиз T2](https://rf.t2.ru/about/news-list/2026/11/06/t2-vydelil-mixx-v-samostoyatelnyj-brend-i-zapustil-prilozhenie-dlya-podpiski-fed) · [решения](decisions.tsv).

В шести VPN-прогонах 82 запроса. У 73 есть подтверждённый выход RU, проверка сертификата и наблюдаемый HTTP-статус. В это число входят ошибки HTTP и первые переходы, а не только рабочие страницы. Два выхода из разных ASN не дают гарантии для всех российских сетей. Globalping не использован. [Машинная сводка](wave-summary.json).

У старого `megafon.tv` оба российских выхода подтвердили HTTPS/301 на `smotreshka.tv`, а отдельная проверка публичного корня назначения дала HTTP 200 со строгим TLS и ограниченной выборкой тела. У обоих наблюдаемый AS200976. Добавили только старое точное имя. `www.megafon.tv`, плеер, параметры перехода и учётные записи не проверялись. [Прогон](vpn-43738312686-megafon-media.tsv) · [неизменность публикации](publication-invariance.tsv).
