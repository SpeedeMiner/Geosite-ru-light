# GeoSite RU Light

Компактная база доменных правил для **раздельной маршрутизации России, Беларуси и Казахстана**. Помогает направлять региональные сервисы напрямую, а для остальных сайтов выбирать маршрут отдельно. В центре проекта не список блокировок, а покрытие сервисов: от банков, доставки и госуслуг до ЭДО, облачных API, медиа и форумов. Это доменная база GeoSite, а не база IP-адресов GeoIP.

**Срез [v11.21](https://github.com/SpeedeMiner/Geosite-ru-light/releases/tag/v11.21):** 4 619 правил `RU` (3 064 суффиксных и 1 555 точных), 44 правила `BLOCK` и 1 003 правила в 16 отдельных категориях Hydra. Всего 18 категорий и 114 562 байта в DAT. В [GeoSite RU Server v11.21](https://github.com/SpeedeMiner/Geosite-ru-server/releases/tag/v11.21) — одна категория `RU` с 4 507 правилами.

## Что отличает сборку

- **Точные правила вместо широких исключений.** `full:` добавляет только нужный хост, например API, кабинет или CDN-зависимость сервиса. Выбранные зоны России, Беларуси и Казахстана свёрнуты в суффиксы. Глобальные зоны `.com`, `.net` и `.org` целиком в `RU` не добавляются. `4pda.to`, `habr.com` и их поддомены не покрываются `RU`. [Проверка доступа из РФ](docs/research/2026-11-20-ru-geoblock/README.md).
- **Списки источников проходят отбор.** Сборщик использует выбранные категории и положительные правила, удаляет дубли и вложенные правила. Блокировочные ленты не превращаются в DIRECT. В Light локальный `BLOCK` и отдельные наборы Hydra не смешиваются с `RU` и могут получить свои действия в конфигурации клиента.
- **Есть собственное исследование и проверяемые правки.** Для новых точечных правил фиксируются принадлежность хоста, публичный HTTPS-путь и, где это требовалось, результаты из независимых российских сетей. Успешный GET не приравнивается к рабочему входу, оплате или видеопотоку. В [v11.21](docs/v11-21-reviewed-services.md) вошли 172 таких точных правила без удалений и без изменений остальных категорий. [Журнал исследования](https://github.com/SpeedeMiner/Geosite-ru-light/blob/research/geosite-ru-wide-20261114-1810/docs/research/2026-11-14-wide-post-v11-18/JOURNAL.md)
- **Публикация проверяется до выкладки.** Номерные сборки воспроизводятся из зафиксированных входов с SHA-256. CI сравнивает покрытие с действующим выпуском, проверяет точные правила и суффиксы в SRS и MRS после декомпиляции и не пропускает неутверждённые добавления. [Воспроизводимость](docs/reproducible-build.md) · [Откат](docs/release-recovery.md)

## Вклад источников в RU

**Локальный список добавляет 1 667 правил, которые не покрываются внешними источниками в этой сборке.** Это **36,09%** готового `RU`: 1 555 точных хостов и 112 суффиксов. Без `local/ru.txt` остаётся **2 952 правила** при тех же внешних источниках, 18 настроенных корнях и той же политике фильтрации. Локальный список увеличивает эту базу на **56,47%**. Вместе с 18 корнями вклад проекта, по атрибуции сборщика, составляет **1 685 правил (36,48%)**, вклад внешних входов — **2 934 (63,52%)**.

| Источник правил RU | Правил в сборке | Доля RU | Выпадет без этого входа |
| --- | ---: | ---: | ---: |
| [Локальный список проекта](local/ru.txt) | 1 667 | 36,09% | 1 667 |
| [Runetfreedom](https://github.com/runetfreedom/russia-blocked-geosite) | 1 594 | 34,51% | 142 |
| [DigneZzZ/routing](https://github.com/DigneZzZ/routing) | 827 | 17,90% | 0 |
| [Hydra / roscomvpn-geosite](https://github.com/hydraponique/roscomvpn-geosite) | 175 | 3,79% | 3 |
| [Davoyan / category-ru-legacy](https://github.com/Davoyan/mihomo-rule-sets) | 139 | 3,01% | 139 |
| [mvrvntn/routing](https://github.com/mvrvntn/routing) | 86 | 1,86% | 56 |
| [w1zardz / ru-direct-domains](https://github.com/w1zardz/amnezia-vpn-russia-split-tunneling) | 43 | 0,93% | 43 |
| [GrimbirdUsers / ru-routing-dat](https://github.com/GrimbirdUsers/ru-routing-dat) | 40 | 0,87% | 34 |
| [Корни, настроенные проектом](tools/ru-geosite-filter/common.go) | 18 | 0,39% | — |
| [Yularzhi / geosite_russia](https://github.com/Yularzhi/geosite_russia) | 16 | 0,35% | 16 |
| [vpnyasha/geosite](https://github.com/vpnyasha/geosite) | 9 | 0,19% | 8 |
| [kyoresuas / ru-direct](https://github.com/kyoresuas/ru-direct) | 4 | 0,09% | 4 |
| [kirilllavrov / RU-domain-list-for-whitelist](https://github.com/kirilllavrov/RU-domain-list-for-whitelist) | 1 | 0,02% | 1 |
| [v2fly / domain-list-community](https://github.com/v2fly/domain-list-community), прямой импорт | 0 | 0,00% | 0 |
| **Итого RU** | **4 619** | **100%** | — |

Доли рассчитаны **по правилам в готовой категории RU**, а не по количеству сайтов, трафику или доле Рунета. Повторяющееся правило засчитано один раз, первому входу по фактическому порядку сборки. Для последнего столбца входы исключались **по одному** при неизменных остальных источниках и политике точности. Считалось покрытие, потерянное относительно опубликованного DAT, с учётом суффиксов. Столбец не суммируется. Например, DigneZzZ даёт 827 правил по порядку загрузки, но в этом срезе остальные входы их покрывают. Прямой импорт v2fly не дал отдельной дельты, однако v2fly также определяет выбор категорий в DAT Runetfreedom. Числа Hydra в таблице относятся только к `RU`. Другие 16 категорий Hydra и локальный `BLOCK` посчитаны отдельно.

Расчёт сделан на [закреплённых входах v11.21](https://github.com/SpeedeMiner/Geosite-ru-light/blob/v11.21/data/geosite-inputs.lock.json). Полная пересборка побайтно совпала с опубликованным DAT. Варианты без одного входа — измерение перекрытий, а не выпуски для использования. «Локальный» означает, что правило пришло из файла проекта и не покрывается другими входами этой сборки. Это не означает, что домена нет ни в одном другом публичном списке.

## Скачать и подключить

| Назначение | Файл |
| --- | --- |
| Xray / V2Ray, Light | [`geosite_RU.dat` из latest-optimized](https://github.com/SpeedeMiner/Geosite-ru-light/releases/download/latest-optimized/geosite_RU.dat) |
| sing-box, `RU` | [`geosite_RU.srs`](https://raw.githubusercontent.com/SpeedeMiner/Geosite-ru-light/release/geosite_RU.srs) |
| sing-box, `BLOCK` | [`geosite_BLOCK.srs`](https://raw.githubusercontent.com/SpeedeMiner/Geosite-ru-light/release/geosite_BLOCK.srs) |
| sing-box, отдельные категории Hydra | [Все SRS в ветке release](https://github.com/SpeedeMiner/Geosite-ru-light/tree/release) |
| mihomo, `RU` | [`geosite_RU.mrs`](https://raw.githubusercontent.com/SpeedeMiner/Geosite-ru-light/release/geosite_RU.mrs) · [jsDelivr](https://cdn.jsdelivr.net/gh/SpeedeMiner/Geosite-ru-light@release/geosite_RU.mrs) |
| mihomo, `BLOCK` | [`geosite_BLOCK.mrs`](https://raw.githubusercontent.com/SpeedeMiner/Geosite-ru-light/release/geosite_BLOCK.mrs) · [jsDelivr](https://cdn.jsdelivr.net/gh/SpeedeMiner/Geosite-ru-light@release/geosite_BLOCK.mrs) |
| mihomo, отдельные категории Hydra | [Все MRS в ветке release](https://github.com/SpeedeMiner/Geosite-ru-light/tree/release) |
| GeoSite Server, только `RU` | [Отдельная серверная сборка](https://github.com/SpeedeMiner/Geosite-ru-server/releases) |
| Проверка SHA-256 | [DAT](https://github.com/SpeedeMiner/Geosite-ru-light/releases/download/latest-optimized/geosite_RU.dat.sha256sum) · [все SRS](https://github.com/SpeedeMiner/Geosite-ru-light/releases/download/latest-optimized/geosite_srs.sha256sum) · [`geosite_mrs.sha256sum`](https://github.com/SpeedeMiner/Geosite-ru-light/releases/download/latest-optimized/geosite_mrs.sha256sum) ([raw](https://raw.githubusercontent.com/SpeedeMiner/Geosite-ru-light/release/geosite_mrs.sha256sum) · [jsDelivr](https://cdn.jsdelivr.net/gh/SpeedeMiner/Geosite-ru-light@release/geosite_mrs.sha256sum)) |

Для фиксированной конфигурации используйте [номерные релизы](https://github.com/SpeedeMiner/Geosite-ru-light/releases). Плавающий `latest-optimized` и ветка `release` обновляются после проверок, в том числе по понедельникам в 00:00 UTC на свежих входах. Неутверждённые новые правила отправляются на ручную проверку. В ветке CDN доступны DAT, SRS, MRS и манифест MRS. Все контрольные суммы хранятся в GitHub Releases. Если jsDelivr ещё отдаёт старый кеш, используйте GitHub Release или файл по SHA коммита ветки `release` и проверьте хэш.

В Xray указывайте `geosite:ru` и `geosite:block` в правилах маршрутизации. Сам файл DAT не назначает выходы. Доступны также [DAT через jsDelivr](https://cdn.jsdelivr.net/gh/SpeedeMiner/Geosite-ru-light@release/geosite_RU.dat) и [RU SRS через jsDelivr](https://cdn.jsdelivr.net/gh/SpeedeMiner/Geosite-ru-light@release/geosite_RU.srs).

### Пример для sing-box

Добавьте элемент в массив `route.rule_set`:

```json
{
  "type": "remote",
  "tag": "geosite-ru",
  "format": "binary",
  "url": "https://raw.githubusercontent.com/SpeedeMiner/Geosite-ru-light/release/geosite_RU.srs"
}
```

Укажите этот тег в `route.rules[].rule_set` и назначьте нужное действие. SRS публикуются в бинарном формате v1. Точное правило DAT становится `domain`, суффикс — `domain_suffix`. Сами наборы не задают `DIRECT`, `PROXY` или блокировку. Если используете `BLOCK` и отдельные категории как исключения из `RU`, расположите их правила раньше `RU`.

### Повторная сборка SRS из DAT

На Linux x86-64 из корня репозитория, с пустой папкой для результата:

```sh
bash tools/build_geosite_srs.sh --dat /path/to/geosite_RU.dat --output-dir srs
(cd srs && sha256sum --check --strict geosite_srs.sha256sum)
```


### mihomo

```yaml
rule-providers:
  geosite-ru:
    type: http
    behavior: domain
    format: mrs
    url: https://raw.githubusercontent.com/SpeedeMiner/Geosite-ru-light/release/geosite_RU.mrs
    path: ./rules/geosite_RU.mrs
    interval: 86400

rules:
  - RULE-SET,geosite-ru,DIRECT
```

Направление `DIRECT` в примере задаёт конфигурация, а не сам набор. Для
`BLOCK` и категорий Hydra используйте отдельные провайдеры с соответствующими
именами файлов. Если они должны иметь приоритет над `RU`, поставьте их
правила раньше.

Пересборка из готового DAT на Linux x86-64 использует закреплённый
официальный mihomo и проверяет точные домены и суффиксы после декомпиляции.

```sh
bash tools/build_geosite_mrs.sh --dat /path/to/geosite_RU.dat --output-dir mrs
(cd mrs && sha256sum --check --strict geosite_mrs.sha256sum)
```

Для офлайн-сборки и сверки с опубликованными байтами см.
[воспроизводимую сборку MRS](docs/reproducible-build.md#reproduce-mihomo-mrs-offline).


## RU-BLOCKED

Отдельный набор из upstream `ru-blocked` (`geosite-ru-only.dat`) проходит DNS-проверку по базе DIRECT проекта Geoip-ru-server и проверку HTTPS-ответа на порту 443 с SNI. Домены из Phishing Army и HaGeZi TIF исключаются до сетевого запроса. Редиректы на HTTP и известные парковочные хосты, а также первые 64 КиБ ответа с известными признаками парковки отклоняются. Проверяется доверие к сертификату и соответствие имени каждого HTTPS-хоста. Для окончательного ответа допустимы только 2xx и 401; ответ 403 отклоняется, включая возможные срабатывания WAF; пустые или тривиальные ответы 200 отклоняются. Редиректы на адреса вне DIRECT отклоняются; HTTP на порту 80 не используется. Списки и сигнатуры неполны и могут ошибаться. Доступность с раннера GitHub не исключает геоблокировки или проблем маршрута в пользовательских сетях. Принадлежность к DIRECT не является определением геолокации. Правила `full` и `domain` сохраняют исходную семантику; проверка домена не подтверждает доступность и IP его поддоменов. Категория не добавляется в RU. Workflow формирует отдельные DAT, SRS и MRS и статистику в артефакте Actions; это не публикация в существующий выпуск или CDN. Кэш живых результатов действует 7 дней, остальных от 1 до 3 дней. Доступность и DNS зависят от точки проверки GitHub Actions.


Ручные исключения для `RU-BLOCKED` задаются в [`data/ru-blocked-exclude.txt`](data/ru-blocked-exclude.txt): пустые строки и комментарии `#` игнорируются, голое имя и `domain:` исключают суффикс, `full:` — точное имя. Если существующее суффиксное правило покрывает исключённый хост или суффикс, удаляется всё это широкое правило: форматы набора не поддерживают внутреннее исключение. Отчёт указывает число затронутых исходных правил и число прошедших проверки правил, которые исключены вручную. Фильтр поиска заглушек нормализует регистр, пробелы и `ё`/`е`; сигнатуры могут ошибаться и не охватывают все случаи.
