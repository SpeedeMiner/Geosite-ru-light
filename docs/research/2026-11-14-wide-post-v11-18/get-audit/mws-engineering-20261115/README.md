# Публичные инженерные хосты MWS и крупных российских групп

Срез 15 ноября 2026. Подтверждение связи компании с проектом, назначение хоста, BGP origin и доступность из RU учитываются отдельно. Выпущенная база служит точкой отсчёта, исследовательская очередь считается отдельно.

| Материал | Содержание |
| --- | --- |
| [Организации](organization-catalog-01.tsv) · [MWS](mws-projects-01.tsv) | Метаданные публичных репозиториев и квитанции README. Для Avito и Контура только первые 100 результатов; Rostelecom-IT не включён в метрики API. |
| [MWS](catalog-coverage-main-01.tsv) · [Nexign и TData](catalog-coverage-other-01.tsv) · [VK, Cloud.ru, Сбер](catalog-coverage-extra-01.tsv) · [Яндекс и остальные](catalog-coverage-extended-01.tsv) | Таблицы `catalog-coverage-*.tsv` содержат 322 записи из 50 открытых источников. Это строки упоминаний, а не 322 кандидата. Навигация, картинки, примеры и внешние ссылки отмечены отдельно. Части с одним префиксом составляют один набор. |
| [DNS](dns-01.tsv) · [RIS](bgp-01.tsv) · [HTTPS](workspace-https-01.tsv) | DNS A/AAAA двух резолверов, наблюдаемые origins RIPE RIS и HTTPS из рабочей сети без региональной атрибуции. Такие запросы не заменяют сеть RU. |
| [DNS повтор](followup-dns-01.tsv) · [RIS повтор](followup-bgp-01.tsv) · [HTTPS повтор](followup-workspace-https-01.tsv) | Отдельный срез DivKit, Kaspersky, Nexign и Taiga UI. |
| [первая выборка MWS](vpn-43732416165.tsv) · [повтор MWS](vpn-43732747610.tsv) · [DivKit и Nexign](vpn-43732966964.tsv) · [Kaspersky](vpn-43733198191.tsv) | Ранее зафиксированные четыре прогона, из них 30 HTTP-ответов. Переходы по Location отключены. Квитанции связывают план, head и хэш архива. Счётчик Globalping нулевой, результаты не зачтены как свежие RU-измерения основного конвейера. |
| [Очередь +59](stacked-fifty-nine.txt) · [локальный replay](full-build-replay-fiftynine.tsv) | Промежуточная чистая дельта RU Light/Server. Проверены два baseline. Без удаления правил. |

Поля `light_ru`, `server_ru`, `block`, `non_ru` описывают совпадения в проверяемых базах. `NA` не означает пригодность для DIRECT. Для тестов публикуются хэши, коды и безопасные части URL, не публикуются тела запросов или параметры перенаправлений.

`taiga-ui.dev` связан с публичным проектом и каталогом Т-Банка. Наблюдаемые A/AAAA совпали с официальным пулом [GitHub Pages](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site) и пришли из AS54113. Это общий хостинг, не ASN Т-Банка. По окончании RU-проверки решение будет касаться только точного домена.

`www.nexign.com` и канонический `nexign.com` наблюдались на AS48102. В рабочей сети проверены три отдельные операции без автоматического перехода: HTTPS WWW → HTTP корень, HTTP корень → HTTPS корень, HTTPS корень → 200. WWW оставлен вне очереди из-за снижения схемы, клиентский портал — из-за 403. `neonhrm.nexign.com`, `job.nexign.com`, `tdata.tech` и `docs.tdata.tech` уже находятся в предыдущей очереди, дубликатов нет.
