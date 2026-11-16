# CDN и видеосервисы — 16 ноября 2026

База — опубликованные GeoSite Light/Server v11.20. Ветка исследовательская, выпуск не запускался.

[Очередь +22](candidate-plus22.txt) сохраняет [прежние пять точных имён LiveDigital](../selcdn-20261116/candidate-plus5.txt) и добавляет 17 из текущей волны. [Поимённые решения](decisions.tsv) и [подтверждения по двум ASN](verified-exacts.tsv) связывают exact с публичным путём, доказательством и причиной отказа для остальных. [Матрица первичного покрытия](baseline-coverage.tsv) — отдельная выборка, не перепись всех имён провайдеров.

- [DAT-превью](dat-preview.tsv): Light 4 469, Server 4 357, изменения только в RU, +22/−0.
- [Все 18 SRS](srs-43811433910.tsv): в сравнении с опубликованным манифестом меняется только RU. [Прогон](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/43811433910).
- [DNS Google/Cloudflare, RIPE и origin](dns-rir-origin-43811108353.tsv), [разница регионального назначения Ivideon](ivideon-vantage-origin.tsv). Наблюдение DNS не эквивалентно доступности в стране и не задаёт диапазоны GeoIP.
- [Сводка и проверенные SHA-256 архивов](wave-summary.json): 95 записей по 43 URL, 88 HTTP-ответов со строгим TLS из трёх российских ASN, 0 Globalping.

## Матрицы публичных GET

- [services-plan.tsv](services-plan.tsv) · [наблюдения 43809865357](vpn-43809865357.tsv) · [Actions](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/43809865357)
- [video-cloud-plan.tsv](video-cloud-plan.tsv) · [наблюдения 43810019298](vpn-43810019298.tsv) · [Actions](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/43810019298)
- [trassir-plan.tsv](trassir-plan.tsv) · [наблюдения 43810171834](vpn-43810171834.tsv) · [Actions](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/43810171834)
- [followup-plan.tsv](followup-plan.tsv) · [наблюдения 43810427670](vpn-43810427670.tsv) · [Actions](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/43810427670)
- [dependencies-plan.tsv](dependencies-plan.tsv) · [наблюдения 43810542095](vpn-43810542095.tsv) · [Actions](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/43810542095)
- [distribution-plan.tsv](distribution-plan.tsv) · [наблюдения 43810699705](vpn-43810699705.tsv) · [Actions](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/43810699705)
- [official-downloads-plan.tsv](official-downloads-plan.tsv) · [наблюдения 43810901374](vpn-43810901374.tsv) · [Actions](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/43810901374)
- [legacy-docs-plan.tsv](legacy-docs-plan.tsv) · [наблюдения 43811286774](vpn-43811286774.tsv) · [Actions](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/43811286774)

TLS и HTTP наблюдались по IPv4. Выходные IP не включены. HTTP 301 подтверждает только перенаправление, 404 — ответ на отдельный путь, curl 28 или отсутствие TLS — отсутствие пригодного результата, а не доказательство блокировки. Файлы Ivideon проверялись только диапазоном 0–511 без установки. Ни логины, ни API с токенами, ни видеопотоки не проверялись.

Широкие правила CDN не менялись. `trueconf.com`, `developers.trueconf.com`, `bx-static.ivideon.com`, глобальный VideoMost и международный `www.trassir.com` остаются вне текущей очереди.
