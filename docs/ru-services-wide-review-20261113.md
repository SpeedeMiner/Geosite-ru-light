# GeoSite RU v11.15 — расширенная проверка покрытия

Проверены опубликованные [Light v11.15](https://github.com/SpeedeMiner/Geosite-ru-light/releases/tag/v11.15) и [Server v11.15](https://github.com/SpeedeMiner/Geosite-ru-server/releases/tag/v11.15). SHA‑256 обоих DAT совпали с релизами. Сопоставление выполнено по фактическим exact/suffix-правилам, а не поиском строки в исходном файле.

Проверены 227 уникальных имён в ЭДО, связи, обучении, облаках, платежах, логистике, картах, ИБ, медицине и инфраструктуре. 134 уже в RU обеих сборок. 93 не совпали с RU в обеих. Отсутствие в DAT не подтверждает принадлежность или полезность. Для 41 имён сделаны анонимные HTTPS GET из AS12389, AS3216 и AS207957.

## 15 подтверждённых точных правил RU

У каждого есть первичный источник, нет совпадения с RU и BLOCK в Light и с RU в Server, а цепочка TLS и имя сертификата проверены на всех трёх точках. Статусы в таблице одинаковы на всех трёх.

| Сектор | Точное правило | Назначение | Источник | Замер |
| --- | --- | --- | --- | --- |
| Связь | `full:app.pachca.com` | Веб-клиент «Пачки» | [Первичный источник](https://pachca.com/help-center/administration/porty-i-adresa-dlya-korrektnoy-raboty-pachki) | [200 × 3](https://api.globalping.io/v1/measurements/2vG6cj1Kpjo6FrLTG00021Utv) |
| Связь | `full:api.pachca.com` | Документированный API «Пачки», GET /api/shared/v1/profile без токена | [Первичный источник](https://dev.pachca.com/api/requests-responses) | [401 × 3](https://api.globalping.io/v1/measurements/290FuhYPN0NBM5b0Y00021Utv) |
| Связь | `full:pachca.com` | Официальный сайт «Пачки» | [Первичный источник](https://pachca.com/legal) | [200 × 3](https://api.globalping.io/v1/measurements/2LZITDF2WCn5cTwnr00021Utv) |
| Связь | `full:dev.pachca.com` | Документация и интеграции «Пачки» | [Первичный источник](https://dev.pachca.com/) | [200 × 3](https://api.globalping.io/v1/measurements/2OhfxpXaGtLnT7gfS00021Utv) |
| Связь | `full:status.pachca.com` | Официальный статус сервисов «Пачки» | [Первичный источник](https://pachca.com/help-center/administration/porty-i-adresa-dlya-korrektnoy-raboty-pachki) | [200 × 3](https://api.globalping.io/v1/measurements/2GS59Zk53U8sknrnh00021Utv) |
| ЭДО и подпись | `full:docsvision.com` | Официальный сайт Docsvision | [Первичный источник](https://docsvision.com/price/licensing-policy/) | [200 × 3](https://api.globalping.io/v1/measurements/2myl6dYAA9xdUNsF200021Utv) |
| ЭДО и подпись | `full:help.docsvision.com` | Эксплуатационная документация Docsvision | [Первичный источник](https://help.docsvision.com/dv6/) | [200 × 3](https://api.globalping.io/v1/measurements/2SqCRa1HPEjSF3W7500021Utv) |
| ЭДО и подпись | `full:www.docsvision.com` | HTTPS-переход на проверенный docsvision.com | [Первичный источник](https://docsvision.com/) | [301 × 3](https://api.globalping.io/v1/measurements/2QCIg992cGgVqHFoP00021Utw) |
| ЭДО и подпись | `full:sign.me` | Официальный сайт сервиса электронной подписи Sign.Me | [Первичный источник](https://sign.me/support/article/kak-zaregistrirovatsia-i-vypustit-unep-esia) | [200 × 3](https://api.globalping.io/v1/measurements/2lIJJWkqewa1rn0UC00021Utw) |
| Облака и CDN | `full:doc.cdnvideo.com` | Русскоязычная документация CDNvideo | [Первичный источник](https://doc.cdnvideo.com/) | [200 × 3](https://api.globalping.io/v1/measurements/2FykRUb2kLBQqXNws00021Utv) |
| Облака и CDN | `full:dashboard.cdnvideo.com` | Адрес панели из официальной инструкции CDNvideo | [Первичный источник](https://doc.cdnvideo.ru/common/ru/api/oauth/) | [200 × 3](https://api.globalping.io/v1/measurements/2SbJnmhW5OwQGKahV00021Utw) |
| Обучение и ВКС | `full:pruffmelab.com` | Хост из требований Pruffme к WebRTC | [Первичный источник](https://pruffme.com/landing/Varton/GaussNEW) | [200 × 3](https://api.globalping.io/v1/measurements/2wfM88PkDWMTnCn0I00021Utw) |
| Телефония | `full:novofon.com` | Сайт и справка российского оператора Novofon | [Первичный источник](https://novofon.com/legal/terms-of-use/) | [200 × 3](https://api.globalping.io/v1/measurements/2xXCy1VjqtxwzjmWV00021Utx) |
| Телефония | `full:api.novofon.com` | Публичная справка Novofon API, без вызова методов | [Первичный источник](https://api.novofon.com/) | [200 × 3](https://api.globalping.io/v1/measurements/2ikwy7Yn2OBLIqFni00021Utx) |
| Данные | `full:arenadc.io` | Документация продукта Arenadata Catalog | [Первичный источник](https://arenadc.io/documentation) | [200 × 3](https://api.globalping.io/v1/measurements/2lBlsiif0MYmXttNG00021Utx) |

У API «Пачки» HTTP 401 с `invalid_token` без токена означает, что отвечает нужный сервис. Это не подтверждение работы авторизованных запросов. У `www.docsvision.com` HTTP 301 ведёт на отдельно проверенный `docsvision.com`. Для панели CDNvideo и Pruffme проверен публичный ответ, вход и медиасессия не проверялись.

## Почему другие имена не предложены

- `payselection.com` — Официальный ресурс, но DNS из трёх точек вернул REFUSED/SERVFAIL. Нет подтверждённого HTTPS. Это не доказательство блокировки. [Замер](https://api.globalping.io/v1/measurements/2BB3DEyf0wsAAnZ1i00021Utv)
- `api.payselection.com` — Та же картина DNS. Не считать рабочим API по ссылке в справке. [Замер](https://api.globalping.io/v1/measurements/2EBqq4aKPTeSMSnoO00021Utv)
- `oferta.payselection.com` — Та же картина DNS. [Замер](https://api.globalping.io/v1/measurements/2fAUIwlpBf6SdmSG100021Utw)
- `doctis.com` — HTTP 200 на парковочной странице с продажей домена. Официальные .ru ресурсы уже покрыты. [Замер](https://api.globalping.io/v1/measurements/2ltAsJGrFGvZnbRN200021Utx)
- `pruffmelab-a.akamaihd.net` — Совместно используемый CDN. Два ответа Invalid URL и одна точка без HTTP не подтверждают нужный функциональный путь. [Замер](https://api.globalping.io/v1/measurements/2vhuz6p2BwfeL2Tdg00021Utw)
- `www.cdnvideo.com` — Глобальная витрина CDNvideo; нет причины добавлять её вместе с документированными рабочими хостами. [Замер](https://api.globalping.io/v1/measurements/2lYcF24Ckv6ubdwzl00021Utx)
- `cdnvideo.com` — Перенаправляет на международную витрину www.cdnvideo.com. [Замер](https://api.globalping.io/v1/measurements/2xg25OCkTth8UrINS00021Utw)
- `www.getcompass.com` — Англоязычная витрина; российский getcompass.ru уже покрыт. Рабочая роль .com для RU-клиента не подтверждена. [Замер](https://api.globalping.io/v1/measurements/2pFAzEhP0ycuHjUa400021Utw)
- `trueconf.com` — Англоязычная витрина; российский trueconf.ru уже покрыт, а конкретные .com-адреса обновления и регистрации уже есть отдельными правилами. [Замер](https://api.globalping.io/v1/measurements/2r3E1MXAzuXTuQBZy00021Utw)
- `ispringlearn.com` — Переход на международный ispringsolutions.com, не подтверждён как необходимый RU endpoint. [Замер](https://api.globalping.io/v1/measurements/2veIJBbyqKsS0NR0U00021Utw)
- `my.novofon.com` — Переход на уже покрытый my.novofon.ru; соглашение указывает кабинет в .ru. [Замер](https://api.globalping.io/v1/measurements/2fLIGWaCXEK1L6ELn00021Utx)
- `tk-kit.com` — Переход на уже покрытый tk-kit.ru. API capi.tk-kit.com уже в обеих сборках. [Замер](https://api.globalping.io/v1/measurements/2jsCVzZt7N2T1KrO100021Utw)
- `dostavista.com` — Переход на уже покрытый dostavista.ru. [Замер](https://api.globalping.io/v1/measurements/2K67vzU7sBJSde05O00021Utw)
- `planfix.com` — Переход на уже покрытый planfix.ru в проверенных сетях. [Замер](https://api.globalping.io/v1/measurements/2ouNKllEWopF7kKGm00021Utw)
- `retailcrm.pro` — Переход на международный www.simla.com; российский retailcrm.ru уже покрыт. [Замер](https://api.globalping.io/v1/measurements/2H6L5La64mU3c4QPV00021Utw)
- `arenadata.io` — Переход на уже покрытый arenadata.tech; docs.arenadata.io уже в обеих сборках. [Замер](https://api.globalping.io/v1/measurements/2NZhDvYn5jhcBNg8600021Utx)

## Границы изменения

В исходник и список разрешённых изменений внесены только перечисленные full-правила. Нет вычитания, новых суффиксов, изменений BLOCK, GeoIP или закреплённых источников. Server формируется из опубликованной Light и сохраняет только категорию RU.
