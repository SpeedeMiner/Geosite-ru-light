# Функциональная проверка оставшихся 376 UNKNOWN — 25 ноября 2026

[Поимённая таблица: 376 имён, исходные правила, категория, причина и сигналы риска](audit-376-classification-2026-11-25.csv). Таблица также содержит дополнительную строку icq.com, ранее ALIVE_RESTRICTED. [Исходные результаты](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/45555011119/artifacts/14995431760).

## Итог для 376

| Категория | Количество |
|---|---:|
| INFRASTRUCTURE | 15 |
| ALIVE_RESTRICTED | 17 |
| UNKNOWN | 344 |
| ALIVE_RU, GEO_BLOCKED, PARKED, UNREGISTERED, DEAD | 0 новых подтверждённых |

Группы для направления проверки, не доказательство принадлежности: прочие 239, финансовые названия 59, IPv6/IP 26, FCM 9, локальные имена 13, CDN/игровые 28, названия ICQ 2. Классификация остальных 344 основана на прежних индивидуальных наблюдениях и новых проверках; конкретная причина сохранена в таблице.

## Подтверждённая инфраструктура

- **FCM:** mtalk.google.com и alt1-mtalk.google.com — alt8-mtalk.google.com. [Google](https://firebase.google.com/docs/cloud-messaging/network-configuration) перечисляет все девять имён и порты TCP 5228–5230. С внешнего runner все 27 TCP-попыток соединились. Это подтверждает сетевые узлы, но не проверяет доставку уведомления и доступность портов из РФ. [Наблюдения](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/45556323219/artifacts/14994944701), mtalk.json.
- **Ресурсы CDN:** steamstatic.com, rbxcdn.com, tildacdn.net. Соответственно [Steam](https://store.steampowered.com/), [Roblox](https://www.roblox.com/) и [Tilda](https://tilda.cc/) ссылались на реальные ресурсы поддоменов; проверенные ресурсы вернули HTTP 200. Исходные правила имеют тип domain и охватывают эти поддомены. Файлы URL и результаты — published-assets.json в архиве выше. Это не проверка доступности из РФ.
- **Локальные имена:** asusrouter.com, router.asus.com, tendawifi.com. [ASUS](https://www.asus.com/support/faq/1045854/), [ASUS router.asus.com](https://zentalk.asus.com/t5/faq/wireless-router-error-message-hsts-appears-when-log-in-to-asus/ta-p/408813) и [Tenda](https://www.tendacn.com/api/proxy-pdf?urlB64=aHR0cHM6Ly9zdGF0aWMudGVuZGEuY29tLmNuL2RvYy8yMDI1LzExLzEzLzc1OWM0YTg3MWFmOTRlMjNiN2ExYWFlZjFiYjZhOWE1L1F1aWNrIEluc3RhbGxhdGlvbiBHdWlkZSgyNSBMYW5ndWFnZXMpLnBkZg%3D%3D) документируют локальную панель. Для практического применения требуется локальная сеть соответствующего устройства; выбор DIRECT относительно других локальных правил остаётся вопросом политики.

Остальные похожие CDN и локальные имена по одному названию не переклассифицированы. Wildberries из runner ответил 498; у VK загрузка страницы сама по себе не подтвердила проверяемые CDN.

## IPv6

Контроль на macOS runner сначала ошибочно принял IPv4-mapped IPv6-адрес; этот результат недействителен. [Исправленный контроль](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/45556588317/artifacts/14995118761) выявил отсутствие маршрута к двум нативным IPv6-адресам. Поэтому использован [Globalping с одним и тем же внешним узлом и контрольным HTTPS по нативному IPv6](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/45556758037/artifacts/14995819008). Это одна точка в Нигерии, не российская.

Ответили 17: 6.ipquail.com, 6.wsmdn.top, checkipv6.dedyn.io, ip6.8n1.org, ip6.anysrc.net, ip6.hostux.net, ip6.istatmenus.app, ip6.nnev.de, ip6only.me, ipv6-check-perf.radar.cloudflare.com, ipv6-test.com, ipv6.ddnspod.com, ipv6.hostux.net, ipv6.mudgee.host, ipv6.nsupdate.info, ipv6.nsx.de, ipv6.pry.sh. 16 вернули HTTP 200, ip6.anysrc.net — 302 без проверки конечного содержимого. Сертификат ipv6-test.com не прошёл проверку точки. Ответ не доказывает полноценную работу или доступность в РФ; поэтому категория ALIVE_RESTRICTED. Неответившие имена остались UNKNOWN с причиной в таблице.

## Банки и защитные списки

Группа из 59 отобрана по имени и может содержать совпадения, не относящиеся к банкам. 9 регистрационных объектов подтверждены исходным RDAP, ещё 32 — прямым RDAP реестра после 429 от посредника. Оставшиеся не подтверждены этим дополнительным проходом; RDAP 404 для alfabank.gcdn.co не доказывает отсутствия регистрации gcdn.co, поскольку это поддомен. Регистрация не доказывает принадлежность банку, назначение и безопасность. Ответы: financial-rdap.json и registry-direct.json в [основном архиве](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/45556323219/artifacts/14994944701) и [архиве уточнения](https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/45556588317/artifacts/14995898455).

Phishing Army и OpenPhish загружены полностью, точных совпадений с проверенной областью не обнаружено. HaGeZi TIF первоначально был недоступен по устаревшему адресу; полная загрузка через актуальный адрес дала точное совпадение **telega.info** и совпадения с отдельными дочерними именами под **at.ua**. Это сигналы для ручной оценки: точное совпадение не является самостоятельным доказательством мошенничества, а дочерние имена не делают весь общий хостинг at.ua фишинговым. Отсутствие совпадения в фидах не подтверждает безопасность. Хэши и совпадения сохранены в feeds.json и hagezi.json.

## ICQ

[VK](https://corp.vkcdn.ru/media/files/VK_News_digest_IR_27_May_2024.pdf) объявила закрытие ICQ 26 июня 2024 года, а [icq.com](https://icq.com/desktop/en) публикует сообщение об остановке. Для **icq.com** меняется вывод: исходный мессенджер прекращён (DEAD), хотя информационная страница отвечает. Правило domain:icq.com охватывает поддомены, поэтому это кандидат на отдельное рассмотрение, не автоматическое безопасное удаление. Ещё 41 имя, ранее ALIVE_RESTRICTED и содержащее icq, не признано устаревшим только по названию: не доказаны принадлежность и текущее назначение каждого. icq.lt и icqmail.net входят в 344 UNKNOWN.

## Итог для исторических 4 495 FQDN

| Категория | Количество |
|---|---:|
| ALIVE_RU | 2 254 |
| ALIVE_RESTRICTED | 1 846 |
| INFRASTRUCTURE | 19 |
| GEO_BLOCKED | 0 подтверждённых |
| PARKED | 0 подтверждённых |
| UNREGISTERED | 31 |
| DEAD | 1 |
| UNKNOWN | 344 |

Набор исторический: прежние 29 незарегистрированных доменов уже исключены из актуального main. Новых незарегистрированных при этом проходе не подтверждено; прежние кандидаты vtbkep.site и xn--90aifd0aza.site требуют перепроверки регистрации перед изменением. Изучить отдельно icq.com и сигнал telega.info; не исключать их автоматически. PR №46 остаётся Draft; правила RU и публикации не менялись.
