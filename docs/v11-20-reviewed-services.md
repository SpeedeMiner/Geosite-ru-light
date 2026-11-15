# GeoSite RU Light v11.20

Относительно v11.19 в RU добавилось 110 точных правил `full:`: 108 имён из закрытой исследовательской очереди и два адреса IP-чекеров. Удалений и новых суффиксов нет. BLOCK и остальные 16 категорий без изменений.

- [Закрытая очередь из 108 имён](https://github.com/SpeedeMiner/Geosite-ru-light/blob/570ace1b1e265e86774af8ea91c54b03c844e0f3/docs/research/2026-11-14-wide-post-v11-18/get-audit/ix-cdn-20261115/stacked-plus108.txt) и [журнал с первичными источниками и наблюдениями](https://github.com/SpeedeMiner/Geosite-ru-light/blob/570ace1b1e265e86774af8ea91c54b03c844e0f3/docs/research/2026-11-14-wide-post-v11-18/JOURNAL.md). В очереди есть точные адреса кабинетов и поддержки операторов, публичной документации, медиасервисов, IX, CDN и облаков. Проверки публичных HTTPS-путей не подтверждают работу авторизации, платежей или трансляций.
- `full:api.tgip.eu` и `full:ipv4.ippubblico.org` вернули фактический IPv4 выхода в четырёх HTTPS 200 со строгим TLS из AS12389 и AS52043. [Таблица и квитанция прогона](https://github.com/SpeedeMiner/Geosite-ru-light/tree/f2fdbf2d66fb21f1be049ee7b43c4493b4988fa7/docs/research/2026-11-14-wide-post-v11-18/get-audit/ip-check-20261115-04).
- Аудит действующего `domain:selcdn.net` остаётся отдельной задачей. Суффикс в этом выпуске не меняется. `tech.vklanding.com` не добавлен. GeoIP не затронут.

Light DAT содержит **4 447 правил RU и 18 категорий**. SHA-256 DAT: `493de38dcb8de4076e8b3659271e92992fc30d3f3b41a4251755af9000cfecf9`.
Ожидаемая серверная проекция содержит **4 335 правил в единственной категории RU**.
Для восстановления закреплён номерной выпуск v11.19.
