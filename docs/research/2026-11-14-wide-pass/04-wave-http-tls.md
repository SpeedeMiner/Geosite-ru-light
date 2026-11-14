# Журнал HTTP/TLS и решения

Наблюдения из RU ASN 12389, 3216 и 207957. Включение требует точного имени и доверенного сертификата. Ответ кэша поиска не заменяет прямое измерение. Пробы не удостоверяют доступность у каждого российского провайдера.

| Точное имя | Путь | HTTP, TLS | Заголовок или редирект | Данные | Итог |
|---|---|---|---|---|---|
| price.myseldon.com | https://price.myseldon.com/ | 200/OK / 200/OK / 200/OK | Seldon.Price — Обоснование начальной максимальной цены контракта | [проверка](https://api.globalping.io/v1/measurements/2A0SDRqxg17d9oaM000021VAJ) | принят по этой пробе |
| help.myseldon.com | https://help.myseldon.com/ | 200/OK / 200/OK / 200/OK | База знаний | [проверка](https://api.globalping.io/v1/measurements/29H11Zbx5nGDwasca00021VAJ) | принят по этой пробе |
| tender.myseldon.com | https://tender.myseldon.com/ | 200/OK / 200/OK / 200/OK | Seldon - Поиск закупок, госзаказ, тендеры | [проверка](https://api.globalping.io/v1/measurements/2pTHRAtT7emIROotM00021VAJ) | принят по этой пробе |
| basis.myseldon.com | https://basis.myseldon.com/ru/landing | 200/OK / 200/OK / 200/OK | Seldon.Basis — поиск и проверка контрагентов | [проверка](https://api.globalping.io/v1/measurements/2CpDp7DS1r7IRRHTp00021VAJ) | принят по этой пробе |
| pro.myseldon.com | https://pro.myseldon.com/en/promo | 200/OK / 200/OK / 200/OK | Seldon.Pro — Successful participation in tenders | [проверка](https://api.globalping.io/v1/measurements/2sRODXJdYZThh72Pt00021VAJ) | принят по этой пробе |
| nexign.com | https://nexign.com/ru/contact-us | 200/OK / 200/OK / 200/OK | Контакты компании Nexign | [проверка](https://api.globalping.io/v1/measurements/2HUvAo7IBdiRUnSbm00021VAK) | принят по этой пробе |
| n3.tech | https://n3.tech/ | 200/OK / 200/OK / 200/OK | ИТ-группа N3.Tech | [проверка](https://api.globalping.io/v1/measurements/2cVUagLUNaSeSO3o500021VAK) | принят по этой пробе |
| nettox.net | https://nettox.net/ | 200/OK / 200/OK / 200/OK | Nettox | [проверка](https://api.globalping.io/v1/measurements/2lMDsBy1RkZDnMyFe00021VAK) | принят по этой пробе |
| el-torg.com | https://el-torg.com/ | 200/OK / 200/OK / 200/OK | Электронная площадка ЭСП | [проверка](https://api.globalping.io/v1/measurements/2yXQJr1NlW0NtBxtp00021VAK) | принят по этой пробе |
| tender.one | https://tender.one/ | 200/OK / 200/OK / 200/OK | Электронная Торговая Площадка - Tender Technologies | [проверка](https://api.globalping.io/v1/measurements/2ADaT6LMmViLzEGGl00021VAK) | принят по этой пробе |
| meets.tender.one | https://meets.tender.one/ | 200/OK / 200/OK / 200/OK | Meets — Сервис для проведения собраний в электронной форме | [проверка](https://api.globalping.io/v1/measurements/2snFUQtMmXge67JIw00021VAK) | принят по этой пробе |
| sunlight.net | https://sunlight.net/ | 200/OK / 200/OK / 200/OK | Ювелирный интернет-магазин SUNLIGHT — купить ювелирные изделия на официальном сайте Санлайт в каталоге с ценами, фото — продажа ювел | [проверка](https://api.globalping.io/v1/measurements/2oyt7gaDBiV9NWkKQ00021VAK) | принят по этой пробе |
| corp.sunlight.net | https://corp.sunlight.net/ | 200/OK / 200/OK / 200/OK | SUNLIGHT — ведущая ювелирная сеть в России | [проверка](https://api.globalping.io/v1/measurements/2J2s7CiS5CIaXr3uT00021VAK) | принят по этой пробе |
| guw.aero | https://guw.aero/ | 200/OK / 200/OK / 200/OK | Международный аэропорт Атырау (GUW) \| Официальный сайт | [проверка](https://api.globalping.io/v1/measurements/2hI6aFIvdYN9mXUyC00021VAK) | принят по этой пробе |
| www.guw.aero | https://www.guw.aero/ | 200/OK / 200/OK / 200/OK | Международный аэропорт Атырау (GUW) \| Официальный сайт | [проверка](https://api.globalping.io/v1/measurements/2jNvXn5sxzgURrEod00021VAK) | принят по этой пробе |
| kazan.aero | https://kazan.aero/ | 200/OK / 200/OK / 200/OK | — | [проверка](https://api.globalping.io/v1/measurements/2Tr68nWoJPGJlpnp600021VAK) | Отложено: HTTP 200 отдаёт JS challenge realauth · [документы](https://kazan.aero/) |
| npo-pas.com | https://npo-pas.com/ | 200/OK / 200/OK / 200/OK | НПО ПАС - КОМПЛЕКСНЫЕ СИСТЕМЫ ГАЗОВОГО ПОЖАРОТУШЕНИЯ | [проверка](https://api.globalping.io/v1/measurements/2vRoJPM2ov5F54Eue00021VAK) | принят по этой пробе |
| www.npo-pas.com | https://www.npo-pas.com/ | 301/OK / 301/OK / 301/OK | https://npo-pas.com/ | [проверка](https://api.globalping.io/v1/measurements/2tJMAOfD0VV0on1xL00021VAK) | принят по этой пробе |
| ru.siberianhealth.com | https://ru.siberianhealth.com/ru/ | 200/OK / 200/OK / 200/OK | Siberian Wellness (Сибирское здоровье) — официальный сайт и интернет-магазин компании в России | [проверка](https://api.globalping.io/v1/measurements/29OfTA5I0qN6uBDQd00021VAK) | принят по этой пробе |
| faberlic.com | https://faberlic.com/ | 303/OK / 303/OK / 303/OK | https://faberlic.com/ru/ru/ | [проверка](https://api.globalping.io/v1/measurements/2980ZEKiLF7KPjYPN00021VAK) | принят по другой пробе |
| www.faberlic.com | https://www.faberlic.com/ | 303/OK / 303/OK / 303/OK | https://faberlic.com/ru/ru/ | [проверка](https://api.globalping.io/v1/measurements/2NaAWrcfPUcHlAiOk00021VAK) | принят по этой пробе |
| www.akosta.info | https://www.akosta.info/akosta/page-content.xhtml?page_unid=5 | 200/— / 200/— / 200/— | А-КОСТА - ЭТП | [проверка](https://api.globalping.io/v1/measurements/2mPLVZXVCNpiG9XM500021VAK) | Отложено: HTTP 200 при недоверенной цепочке TLS · [документы](https://www.akosta.info/) |
| kgf.aero | https://kgf.aero/ru/ | не измерено | no_probes_found | — | повтор проверен, см. ниже |
| www.kgf.aero | https://www.kgf.aero/ru/contacts/ | 200/OK / 200/OK / 200/OK | Контакты | [проверка](https://api.globalping.io/v1/measurements/23GkIiX23uTMot59a00021VAK) | принят по этой пробе |
| cerebrohq.com | https://cerebrohq.com/ | 302/OK / 302/OK / 302/OK | https://cerebrohq.com/en | [проверка](https://api.globalping.io/v1/measurements/293LVX7SIU3GpljAN00021VAK) | Отложено: цепочка редиректов не подтверждена · [документы](https://cerebrohq.com/ru/company/) |
| www.usergate.com | https://www.usergate.com/ | 301/OK / 301/OK / 301/OK | https://usergate.com/ | [проверка](https://api.globalping.io/v1/measurements/23gOlOGKfzurp4CD500021VAK) | принят по этой пробе |
| istock.link | https://istock.link/ | 200/OK / 200/OK / 200/OK | Автоматизация закупок и продаж: SRM и CRM \| iStockLink | [проверка](https://api.globalping.io/v1/measurements/2fiK0C13dM91vOpAy00021VAK) | принят по этой пробе |
| abcfood.net | https://abcfood.net/ | 200/OK / 200/OK / 200/OK | ОДО «ФИРМА ABC» — Здоровые продукты! | [проверка](https://api.globalping.io/v1/measurements/2TQSLLCrtlhxDe2BR00021VAK) | принят по этой пробе |
| asapcg.com | https://asapcg.com/ | 200/OK / 200/OK / 200/OK | Автоматизация производства на 1C:ERP/MES/APS систем - АСАП Разработка | [проверка](https://api.globalping.io/v1/measurements/2DGTum1zfdaIqc7Wx00021VAK) | принят по этой пробе |
| faberlic.com | https://faberlic.com/ru/ru/ | 200/OK / 200/OK / 200/OK | — | [проверка](https://api.globalping.io/v1/measurements/2Pez3oZ3BOj0enS2800021VAL) | принят по этой пробе |
| kgf.aero | https://kgf.aero/ru/ | 200/OK / 200/OK / 200/OK | Главная | [проверка](https://api.globalping.io/v1/measurements/2kXsWk5Fv9ZD7nSwH00021VAL) | принят по этой пробе |
| cerebrohq.com | https://cerebrohq.com/ru | 200/OK / 200/OK / 200/OK | — | [проверка](https://api.globalping.io/v1/measurements/2yyNHL9N71YzwKb6200021VAL) | Отложено: цепочка редиректов не подтверждена · [документы](https://cerebrohq.com/ru/company/) |
| seldon.org | https://seldon.org/ | 200/OK / 200/OK / 200/OK | Seldon - Поиск тендеров и аналитика | [проверка](https://api.globalping.io/v1/measurements/2vEalaF7CSmOJX2oh00021VAL) | принят по этой пробе |
| konversta.com | https://konversta.com/ | 302/OK / 302/OK / 302/OK | https://konversta.com/ru/ | [проверка](https://api.globalping.io/v1/measurements/2G8G9zLMHgyTxN4aQ00021VAL) | принят по другой пробе |
| kazan.aero | https://kazan.aero/ | 200/OK / 200/OK / 200/OK | — | [проверка](https://api.globalping.io/v1/measurements/2jhGJbURvmtybbJD100021VAL) | Отложено: HTTP 200 отдаёт JS challenge realauth · [документы](https://kazan.aero/) |
| armtel.com | https://armtel.com/ | 200/OK / 200/OK / 200/OK | Home | [проверка](https://api.globalping.io/v1/measurements/2cWi0Ut4p3KuqHP7v00021VAL) | принят по этой пробе |
| bercut.com | https://bercut.com/ | 200/OK / 200/OK / 200/OK | Компания Bercut – поставщик IT-решений и бизнес-продуктов для операторов связи и провайдеров услуг | [проверка](https://api.globalping.io/v1/measurements/2nZSttv5wfxFFdTzh00021VAL) | принят по этой пробе |
| gigaenterprise.ai | https://gigaenterprise.ai/ | 200/OK / 200/OK / 200/OK | Корпоративная ИИ-платформа ГигаЧат Бизнес | [проверка](https://api.globalping.io/v1/measurements/28JvDb5bHwgjxf5cI00021VAL) | отложено: не хватает сведений |
| fact.digital | https://fact.digital/ | 200/OK / 200/OK / 200/OK | Факт - создание и развитие сайтов и e-commerce проектов на 1С-Битрикс | [проверка](https://api.globalping.io/v1/measurements/2v3OdQttDVH9mAuKe00021VAL) | принят по этой пробе |
| nexign.com | https://nexign.com/ru/ | 301/OK / 301/OK / 301/OK | https://nexign.com/ru | [проверка](https://api.globalping.io/v1/measurements/21q61Lo4HGqb4csoE00021VAL) | принят по другой пробе |
| torggroup.org | https://torggroup.org/ | —/— / —/— / —/— | — | [проверка](https://api.globalping.io/v1/measurements/2cXVvjER8FVFk9E1M00021VAL) | отложено: не хватает сведений |
| lachevsky.group | https://lachevsky.group/ | 200/OK / 200/OK / 200/OK | Разработка ПО для бизнеса - Lachevsky Group | [проверка](https://api.globalping.io/v1/measurements/2KRaRmxOb2vTpDxXL00021VAL) | принят по этой пробе |
| nordclan.com | https://nordclan.com/ | 200/OK / 200/OK / 200/OK | Цифровые и ИИ-решения для бизнеса | [проверка](https://api.globalping.io/v1/measurements/2drYc11hypy7irNCY00021VAL) | принят по этой пробе |
| naveksoft.com | https://naveksoft.com/ru | 200/OK / 200/OK / 200/OK | Naveksoft - Beyond the Usual | [проверка](https://api.globalping.io/v1/measurements/2ktgzwyIUxf75odUo00021VAL) | уже покрыт |
| help.myseldon.com | https://help.myseldon.com/ | 200/OK / 200/OK / 200/OK | База знаний | [проверка](https://api.globalping.io/v1/measurements/22v4pGSGb7yMV3IZ100021VAM) | принят по другой пробе |
| sistematorg.com | https://sistematorg.com/ | 200/OK / 200/OK / 200/OK | Объединенные системы торгов | [проверка](https://api.globalping.io/v1/measurements/2KwSTSAoj9StlyDOJ00021VAM) | отложено: не хватает сведений |
| 101xp.com | https://101xp.com/ | 200/OK / 200/OK / 200/OK | 101XP | [проверка](https://api.globalping.io/v1/measurements/2mizihFqRMOihmwWr00021VAO) | Не включать: оператор услуги за пределами RU/BY/KZ · [документы](https://en.101xp.com/terms) |
| 1cgs.net | https://1cgs.net/ | 200/OK / 200/OK / 200/OK | 1C Game Studios | [проверка](https://api.globalping.io/v1/measurements/2pW2ZGghQsTlMdzn100021VAO) | принят по этой пробе |
| 7winds.mobi | https://7winds.mobi/ | 200/OK / 200/OK / 200/OK | Студия мобильной разработки Seven Winds \| Приложения и игры, AR VR и геймификация | [проверка](https://api.globalping.io/v1/measurements/2Qqoqsm2xjSpI9clo00021VAO) | принят по этой пробе |
| ardor-gaming.com | https://ardor-gaming.com/ | не измерено | no_probes_found | — | отложено |
| fibrum.com | https://fibrum.com/ | 200/OK / 200/OK / 200/OK | Fibrum | [проверка](https://api.globalping.io/v1/measurements/2yvC0FyLy250m7EE100021VAO) | Не включать: доступен, но в документах Fibrum Limited / FIBRUM LLC Cyprus; одноимённое ООО в РФ не устанавливает оператора · [документы](https://fibrum.com/privacy_policy) |
| gfagames.com | https://gfagames.com/ | —/— / —/— / —/— | — | [проверка](https://api.globalping.io/v1/measurements/2DgvtcRRRzxwY3BUA00021VAO) | отложено: не хватает сведений |
| ice-pick.com | https://ice-pick.com/ | 200/OK / 200/OK / 200/OK | I C E - P I C K | [проверка](https://api.globalping.io/v1/measurements/2r2YX9VrdO9LZ8qV400021VAO) | принят по этой пробе |
| kometa.games | https://kometa.games/ | 200/OK / 200/OK / 200/OK | Kometa.Games | [проверка](https://api.globalping.io/v1/measurements/2rIlnHG1AmxM55FBS00021VAO) | Не включать: Yadarko Trading Ltd, Cyprus · [документы](https://kometa.games/privacy-ma.html) |
| kosmos.games | https://kosmos.games/ | 200/OK / 200/OK / 200/OK | Kosmos – A comfortable and reliable gaming company. We have colorful and successful casual games that are played by more than 300,00 | [проверка](https://api.globalping.io/v1/measurements/2YZmMwegqRnekFffp00021VAO) | Не включать: Kosmos Games (Cyprus) Ltd · [документы](https://kosmos.games/privacy/) |
| nebula-gaming.com | https://nebula-gaming.com/ | 301/OK / 301/OK / 301/OK | https://www.nebula-gaming.com/ | [проверка](https://api.globalping.io/v1/measurements/2gJOVNemjvTLiFI3h00021VAO) | Не включать: редирект на сайт другого назначения · [документы](https://www.nebula-gaming.com/) |
| nv-games.com | https://nv-games.com/ | —/— / —/— / —/— | — | [проверка](https://api.globalping.io/v1/measurements/2Efa8jZy0wHiDqe9000021VAO) | отложено: не хватает сведений |
| red-square.org | https://red-square.org/ | 200/OK / 200/OK / 200/OK | — | [проверка](https://api.globalping.io/v1/measurements/237c3tOlAHtCfZFvA00021VAO) | отложено: не хватает сведений |
| vintorog.com | https://vintorog.com/ | 200/OK / 200/OK / 200/OK | Винторог - студия разработки игр, портирование, образование и мероприятия в игровой индустрии | [проверка](https://api.globalping.io/v1/measurements/2zYtyL0QuoEqfDBAa00021VAO) | принят по этой пробе |
| wattstudio.art | https://wattstudio.art/ | не измерено | no_probes_found | — | отложено |
| wefiftytwo.com | https://wefiftytwo.com/ | 200/OK / 200/OK / 200/OK | — | [проверка](https://api.globalping.io/v1/measurements/2AC21CqlGGEsYyeHg00021VAO) | отложено: не хватает сведений |
| www.battlestategames.com | https://www.battlestategames.com/ | 200/OK / 200/OK / 200/OK | Battlestate Games Limited | [проверка](https://api.globalping.io/v1/measurements/28lRl73A3BD4FBj5Q00021VAO) | Не включать: Battlestate Games Limited, UK · [документы](https://www.battlestategames.com/) |
| www.carx-tech.com | https://www.carx-tech.com/ | 301/— / 301/— / 301/— | https://carx-online.com/ | [проверка](https://api.globalping.io/v1/measurements/2qnbbo0HQtmk2Rttn00021VAO) | Отложено: ошибка TLS на алиасе; отдельно проверять актуальное имя · [документы](https://carx-online.com/) |
| www.herocraft.com | https://www.herocraft.com/ | 301/OK / 301/OK / 301/OK | https://herocraft.com/ | [проверка](https://api.globalping.io/v1/measurements/2srQhow64e20kVSIR00021VAO) | отложено: не хватает сведений |
| www.inkstainsgames.net | https://www.inkstainsgames.net/ | —/— / —/— / —/— | — | [проверка](https://api.globalping.io/v1/measurements/2Sz4irZ4fpyrYDJlW00021VAO) | отложено: не хватает сведений |
| www.morteshka.com | https://www.morteshka.com/ | 200/OK / 200/OK / 200/OK | — | [проверка](https://api.globalping.io/v1/measurements/22kSiX9591VlYgULb00021VAO) | отложено: не хватает сведений |
| melnitsa.com | https://melnitsa.com/ | —/— / —/— / —/— | — | [проверка](https://api.globalping.io/v1/measurements/2iSkQHMgxS4lOL8Ic00021VAQ) | отложено: не хватает сведений |
| parovoz.tv | https://parovoz.tv/ | не измерено | no_probes_found | — | повтор проверен, см. ниже |
| www.parovoz.tv | https://www.parovoz.tv/ | 301/OK / 301/OK / 301/OK | https://parovoz.tv/ | [проверка](https://api.globalping.io/v1/measurements/2OsThVUxR2CAaqkBm00021VAQ) | принят по этой пробе |
| yarko.com | https://yarko.com/ | не измерено | no_probes_found | — | отложено |
| www.100kwt.com | https://www.100kwt.com/ | 200/OK / 200/OK / 200/OK | Главная | [проверка](https://api.globalping.io/v1/measurements/2sEK8rMyfCIfXAr0b00021VAQ) | принят по этой пробе |
| 100kwt.com | https://100kwt.com/ | 200/OK / 200/OK / 200/OK | Главная | [проверка](https://api.globalping.io/v1/measurements/2rwDQsaBcT0KPseTU00021VAQ) | принят по этой пробе |
| www.sharstudio.com | https://www.sharstudio.com/ | 200/— / 200/— / 200/— | Домен не привязан к хостингу | [проверка](https://api.globalping.io/v1/measurements/2Iy4YLGd8OSIG5Bnn00021VAQ) | Не включать: парковка и ошибка TLS · [документы](https://www.sharstudio.com/) |
| www.mechtalet.com | https://www.mechtalet.com/ | 301/OK / 301/OK / 301/OK | https://mechtalet.com/ | [проверка](https://api.globalping.io/v1/measurements/2IvEUAuUcYskBOp1d00021VAQ) | принят по этой пробе |
| rgbrosstudio.com | https://rgbrosstudio.com/ | 200/OK / 200/OK / 200/OK | RGBros Studio | [проверка](https://api.globalping.io/v1/measurements/2syCQDm3q2C4TToc100021VAQ) | принят по этой пробе |
| rocketf.com | https://rocketf.com/ | 200/OK / 200/OK / 200/OK | Рокет Фокс — независимая анимационная студия сериалов для детей | [проверка](https://api.globalping.io/v1/measurements/25u2vbEiWCKY2bS6a00021VAQ) | принят по этой пробе |
| multilandia.tv | https://multilandia.tv/ | —/— / —/— / —/— | — | [проверка](https://api.globalping.io/v1/measurements/28BUyevQx6NxTmZTr00021VAQ) | отложено: не хватает сведений |
| www.cerebrohq.com | https://www.cerebrohq.com/ | 302/OK / 302/OK / 302/OK | https://www.cerebrohq.com/en | [проверка](https://api.globalping.io/v1/measurements/2aqP5ctDwkU9AxBxN00021VAQ) | Отложено: цепочка редиректов не подтверждена · [документы](https://cerebrohq.com/ru/company/) |
| www.cgfww.com | https://www.cgfww.com/ | 200/OK / 200/OK / 200/OK | CGF | [проверка](https://api.globalping.io/v1/measurements/2bxFus1n7NDZRbdPi00021VAQ) | принят по этой пробе |
| www.wizartanimation.com | https://www.wizartanimation.com/ | 404/— / 404/— / 404/— | 404 Not Found | [проверка](https://api.globalping.io/v1/measurements/2cVaM1sRVDBGWs7M500021VAQ) | Отложено: 404 и ошибка TLS · [документы](https://www.wizartanimation.com/) |
| konversta.com | https://konversta.com/ru/ | 200/OK / 200/OK / 200/OK | Конверста \| Цифровые технологии для логистики | [проверка](https://api.globalping.io/v1/measurements/2WUaNoByks91vNMN500021VAQ) | принят по этой пробе |
| parovoz.tv | https://parovoz.tv/ | 200/OK / 200/OK / 200/OK | Главная • Анимационная студия «Паровоз» | [проверка](https://api.globalping.io/v1/measurements/2tmkfvaXf6ianK0EX00021VAT) | принят по этой пробе |
| mechtalet.com | https://mechtalet.com/ | 200/OK / 200/OK / 200/OK | Главная - Анимационная студия «Мечталëт» | [проверка](https://api.globalping.io/v1/measurements/2LntOo95irJdw4G9Z00021VAT) | принят по этой пробе |
| cerebrohq.com | https://cerebrohq.com/ru/company/ | 302/OK / 302/OK / 302/OK | https://cerebrohq.com/ru | [проверка](https://api.globalping.io/v1/measurements/2kYRYWj9fHLioE7yW00021VAT) | Отложено: цепочка редиректов не подтверждена · [документы](https://cerebrohq.com/ru/company/) |
| www.cerebrohq.com | https://www.cerebrohq.com/ru/company/ | 302/OK / 302/OK / 302/OK | https://cerebrohq.com/ru | [проверка](https://api.globalping.io/v1/measurements/2TqNokCl7x4H91uFB00021VAT) | Отложено: цепочка редиректов не подтверждена · [документы](https://cerebrohq.com/ru/company/) |
| www.nebula-gaming.com | https://www.nebula-gaming.com/ | 502/OK / 502/OK / 502/OK | — | [проверка](https://api.globalping.io/v1/measurements/2ZvSZIPqj2nGUr1Wm00021VAT) | Не включать: поисковый снимок показывает крикет, живые пробы 502 · [документы](https://www.nebula-gaming.com/) |
| cgfww.com | https://cgfww.com/contact | 200/OK / 200/OK / 200/OK | Contact | [проверка](https://api.globalping.io/v1/measurements/2QGLbzKE5E5aSgO5k00021VAT) | принят по этой пробе |

## Подтверждённые в этом проходе

| Правило | Первичный источник | HTTP/TLS |
|---|---|---|
| `full:100kwt.com` | [источник](https://www.100kwt.com/aboutus) | [замер](https://api.globalping.io/v1/measurements/2rwDQsaBcT0KPseTU00021VAQ) |
| `full:1cgs.net` | [источник](https://1cgs.net/) | [замер](https://api.globalping.io/v1/measurements/2pW2ZGghQsTlMdzn100021VAO) |
| `full:7winds.mobi` | [источник](https://7winds.mobi/contacts) | [замер](https://api.globalping.io/v1/measurements/2Qqoqsm2xjSpI9clo00021VAO) |
| `full:abcfood.net` | [источник](https://agrobelarus.by/company/voda_pitevaya_i_mineralnaya_napitki_bezalkogolnye/firma_avs_odo_g_grodno/) | [замер](https://api.globalping.io/v1/measurements/2TQSLLCrtlhxDe2BR00021VAK) |
| `full:armtel.com` | [источник](https://armtel.com/ru/kontakty/) | [замер](https://api.globalping.io/v1/measurements/2cWi0Ut4p3KuqHP7v00021VAL) |
| `full:asapcg.com` | [источник](https://asapcg.com/contacts/) | [замер](https://api.globalping.io/v1/measurements/2DGTum1zfdaIqc7Wx00021VAK) |
| `full:basis.myseldon.com` | [источник](https://www.aetp.ru/) | [замер](https://api.globalping.io/v1/measurements/2CpDp7DS1r7IRRHTp00021VAJ) |
| `full:bercut.com` | [источник](https://bercut.com/contacts/) | [замер](https://api.globalping.io/v1/measurements/2nZSttv5wfxFFdTzh00021VAL) |
| `full:cgfww.com` | [источник](https://cgfww.com/contact) | [замер](https://api.globalping.io/v1/measurements/2QGLbzKE5E5aSgO5k00021VAT) |
| `full:corp.sunlight.net` | [источник](https://corp.sunlight.net/) | [замер](https://api.globalping.io/v1/measurements/2J2s7CiS5CIaXr3uT00021VAK) |
| `full:el-torg.com` | [источник](https://el-torg.com/) | [замер](https://api.globalping.io/v1/measurements/2yXQJr1NlW0NtBxtp00021VAK) |
| `full:faberlic.com` | [источник](https://faberlic.com/index.php?Itemid=5313&id=65&lang=ru&layout=blog&option=com_content&view=category) | [замер](https://api.globalping.io/v1/measurements/2Pez3oZ3BOj0enS2800021VAL) |
| `full:fact.digital` | [источник](https://fact.digital/contacts/) | [замер](https://api.globalping.io/v1/measurements/2v3OdQttDVH9mAuKe00021VAL) |
| `full:guw.aero` | [источник](https://guw.aero/) | [замер](https://api.globalping.io/v1/measurements/2hI6aFIvdYN9mXUyC00021VAK) |
| `full:help.myseldon.com` | [источник](https://price.myseldon.com/) | [замер](https://api.globalping.io/v1/measurements/29H11Zbx5nGDwasca00021VAJ) |
| `full:ice-pick.com` | [источник](https://ice-pick.com/) | [замер](https://api.globalping.io/v1/measurements/2r2YX9VrdO9LZ8qV400021VAO) |
| `full:istock.link` | [источник](https://istock.link/aboutus) | [замер](https://api.globalping.io/v1/measurements/2fiK0C13dM91vOpAy00021VAK) |
| `full:kgf.aero` | [источник](https://caa.gov.kz/ru/kontakty) | [замер](https://api.globalping.io/v1/measurements/2kXsWk5Fv9ZD7nSwH00021VAL) |
| `full:konversta.com` | [источник](https://konversta.com/ru/information/details/) | [замер](https://api.globalping.io/v1/measurements/2WUaNoByks91vNMN500021VAQ) |
| `full:lachevsky.group` | [источник](https://www.lachevsky.group/dokumentyi/) | [замер](https://api.globalping.io/v1/measurements/2KRaRmxOb2vTpDxXL00021VAL) |
| `full:mechtalet.com` | [источник](https://mechtalet.com/contacts) | [замер](https://api.globalping.io/v1/measurements/2LntOo95irJdw4G9Z00021VAT) |
| `full:meets.tender.one` | [источник](https://tender.one/) | [замер](https://api.globalping.io/v1/measurements/2snFUQtMmXge67JIw00021VAK) |
| `full:n3.tech` | [источник](https://n3.tech/) | [замер](https://api.globalping.io/v1/measurements/2cVUagLUNaSeSO3o500021VAK) |
| `full:nettox.net` | [источник](https://fiata.org/directory/by/) | [замер](https://api.globalping.io/v1/measurements/2lMDsBy1RkZDnMyFe00021VAK) |
| `full:nexign.com` | [источник](https://nexign.com/ru/contact-us) | [замер](https://api.globalping.io/v1/measurements/2HUvAo7IBdiRUnSbm00021VAK) |
| `full:nordclan.com` | [источник](https://nordclan.com/contacts) | [замер](https://api.globalping.io/v1/measurements/2drYc11hypy7irNCY00021VAL) |
| `full:npo-pas.com` | [источник](https://npo-pas.com/info) | [замер](https://api.globalping.io/v1/measurements/2vRoJPM2ov5F54Eue00021VAK) |
| `full:parovoz.tv` | [источник](https://parovoz.tv/contact) | [замер](https://api.globalping.io/v1/measurements/2tmkfvaXf6ianK0EX00021VAT) |
| `full:price.myseldon.com` | [источник](https://price.myseldon.com/services) | [замер](https://api.globalping.io/v1/measurements/2A0SDRqxg17d9oaM000021VAJ) |
| `full:pro.myseldon.com` | [источник](https://www.aetp.ru/) | [замер](https://api.globalping.io/v1/measurements/2sRODXJdYZThh72Pt00021VAJ) |
| `full:rgbrosstudio.com` | [источник](https://rgbrosstudio.com/) | [замер](https://api.globalping.io/v1/measurements/2syCQDm3q2C4TToc100021VAQ) |
| `full:rocketf.com` | [источник](https://rocketf.com/) | [замер](https://api.globalping.io/v1/measurements/25u2vbEiWCKY2bS6a00021VAQ) |
| `full:ru.siberianhealth.com` | [источник](https://ru.siberianhealth.com/ru/shop/page/contacts/) | [замер](https://api.globalping.io/v1/measurements/29OfTA5I0qN6uBDQd00021VAK) |
| `full:seldon.org` | [источник](https://seldon.org/) | [замер](https://api.globalping.io/v1/measurements/2vEalaF7CSmOJX2oh00021VAL) |
| `full:sunlight.net` | [источник](https://corp.sunlight.net/) | [замер](https://api.globalping.io/v1/measurements/2oyt7gaDBiV9NWkKQ00021VAK) |
| `full:tender.myseldon.com` | [источник](https://tender.myseldon.com/company/) | [замер](https://api.globalping.io/v1/measurements/2pTHRAtT7emIROotM00021VAJ) |
| `full:tender.one` | [источник](https://tender.one/) | [замер](https://api.globalping.io/v1/measurements/2ADaT6LMmViLzEGGl00021VAK) |
| `full:vintorog.com` | [источник](https://vintorog.com/) | [замер](https://api.globalping.io/v1/measurements/2zYtyL0QuoEqfDBAa00021VAO) |
| `full:www.100kwt.com` | [источник](https://www.100kwt.com/aboutus) | [замер](https://api.globalping.io/v1/measurements/2sEK8rMyfCIfXAr0b00021VAQ) |
| `full:www.cgfww.com` | [источник](https://www.cgfww.com/) | [замер](https://api.globalping.io/v1/measurements/2bxFus1n7NDZRbdPi00021VAQ) |
| `full:www.faberlic.com` | [источник](https://faberlic.com/tr/ru/register) | [замер](https://api.globalping.io/v1/measurements/2NaAWrcfPUcHlAiOk00021VAK) |
| `full:www.guw.aero` | [источник](https://www.guw.aero/) | [замер](https://api.globalping.io/v1/measurements/2jNvXn5sxzgURrEod00021VAK) |
| `full:www.kgf.aero` | [источник](https://www.kgf.aero/ru/contacts/) | [замер](https://api.globalping.io/v1/measurements/23GkIiX23uTMot59a00021VAK) |
| `full:www.mechtalet.com` | [источник](https://mechtalet.com/contacts) | [замер](https://api.globalping.io/v1/measurements/2IvEUAuUcYskBOp1d00021VAQ) |
| `full:www.npo-pas.com` | [источник](https://npo-pas.com/info/rekvizity-npo-pas) | [замер](https://api.globalping.io/v1/measurements/2tJMAOfD0VV0on1xL00021VAK) |
| `full:www.parovoz.tv` | [источник](https://parovoz.tv/contact) | [замер](https://api.globalping.io/v1/measurements/2OsThVUxR2CAaqkBm00021VAQ) |
| `full:www.usergate.com` | [источник](https://usergate.com/company) | [замер](https://api.globalping.io/v1/measurements/23gOlOGKfzurp4CD500021VAK) |

## Пробная сборка

База Light 3846 RU, Server 3734 RU. Включая 197 ранее подтверждённых, дельта +244.
- `buildcheck/geosite_RU.dat` SHA-256 `7d95a0d84e12fba22dd5c40bc9779633fefc907bddb571da5dc144f8dc4d7719`
- `server/geosite_RU.dat` SHA-256 `917fd85edde06d06e699f25de27fea9a940673b760e94bc62e3d8848a6f9e0a3`
