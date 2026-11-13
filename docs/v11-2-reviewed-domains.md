# GeoSite RU Light v11.2 — reviewed domain promotion

PR #4 is an audit-only source of research context. This release has no
dependency on its live discovery or candidate feeds. It promotes only
first-party rules reviewed against official catalogs, API documentation,
support articles or corporate and regulator records.

- Baseline: immutable v11.1 DAT, SHA-256
  `450f7b0d837671121c34f5a08adc35ef95f845e5abaa35fa47b0d0444a73ca83`.
- Expected effective RU delta: +33 (14 RootDomain, 19 Full), 0 lost.
  Expected RU size: 3086 rules. BLOCK remains 43. No changes are intended
  to the 16 appended Hydra categories or the 4pda.to exclusion.
- The other 24 researched rules remain out of this release. Shared
  infrastructure, foreign CSP-only matches, and unverified parent domains
  are not imported by the research process.
- The local RU source emits the entries. The cumulative approved manifest
  is the promotion gate and is also the build's exact-host policy source.
- The release workflow runs the production semantic gate on the PR before
  publishing, then compares the main build against the floating release.
  v11 and v11.1 tags are not moved.

## Evidence by research batch

| Rule | Purpose | Primary evidence |
|---|---|---|
| `domain:1c-dn.com` | Международный сайт платформы 1С:Предприятие | [Каталог 1С](https://v8.1c.ru/static/drugie-sayty-1s/), [условия сайта 1C Developer Network](https://1c-dn.com/terms/) |
| `domain:1c.market` | Торговая площадка 1С для мелкого опта | [Каталог 1С](https://v8.1c.ru/static/drugie-sayty-1s/), [работающий каталог сервиса](https://1c.market/) |
| `domain:cdek-express.com` | Международный сайт СДЭК | [Прямая ссылка в разделе «Международные сайты»](https://www.cdek.ru/ru/), [международный сайт](https://cdek-express.com/). Это правило также покроет официальный `ecommerce.cdek-express.com` |
| `domain:cdek.media` | Реклама в сети пунктов выдачи СДЭК | [Прямая ссылка «Реклама в экосистеме CDEK»](https://www.cdek.ru/ru/), [страница сервиса](https://cdek.media/) |
| `full:seller.ozon.am` | Витрина Ozon Seller для Армении | [Выбор страны на Ozon Seller](https://seller.ozon.com/), [армянская витрина](https://seller.ozon.am/?__rr=2). Чистый URL не удалось независимо получить, но адрес подтверждён и международной, и казахстанской витринами. Корень `ozon.am` не предлагается |
| `full:seller.ozonru.cn` | Китайская витрина Ozon Seller | [Выбор страны на Ozon Seller](https://seller.ozon.com/), [китайская витрина](https://seller.ozonru.cn/). Корень `ozonru.cn` не предлагается |
| `full:download.ispsystem.com` | Установка и обновления VMmanager 6 и DCImanager 6 | [Сетевые требования VMmanager](https://www.ispsystem.ru/docs/vmmanager-admin/o-platforme/trebovaniya-k-serveru-v2026061), [инструкция по установке](https://www.ispsystem.ru/docs/vmmanager-admin/ustanovka-i-obnovlenie/ustanovka-v2026091-7) |
| `full:docker-registry.ispsystem.com` | Реестр контейнеров продуктов ISPsystem | [Сетевые требования DCImanager](https://www.ispsystem.ru/docs/dcimanager-admin/o-platforme/trebovaniya-k-serveru-v2026111), [инструкция по установке](https://www.ispsystem.ru/docs/dcimanager-admin/ustanovka-i-obnovlenie/ustanovka-v2026091) |
| `full:license6.ispsystem.com` | Проверка лицензий VMmanager 6 и DCImanager 6 | [Сетевые требования VMmanager](https://www.ispsystem.ru/docs/vmmanager-admin/o-platforme/trebovaniya-k-serveru-v2026061), [сетевые требования DCImanager](https://www.ispsystem.ru/docs/dcimanager-admin/o-platforme/trebovaniya-k-serveru-v2026111) |
| `full:my.ispsystem.com` | Личный кабинет ISPsystem и получение токена лицензии | [Лицензирование VMmanager](https://www.ispsystem.ru/docs/vmmanager-admin/o-platforme/litsenzirovanie-v2026051), [установка DCImanager](https://www.ispsystem.ru/docs/dcimanager-admin/ustanovka-i-obnovlenie/ustanovka-v2026091) |
| `full:download.ispmanager.com` | Установщик и пакетный репозиторий ispmanager 6 | [Установка ispmanager](https://www.ispmanager.ru/docs/ispmanager/ustanovka-ispmanager), [диагностика обновлений](https://www.ispmanager.ru/knowledge-base/ne-obnovlyaetsya-panel-ispmanager-6) |
| `full:license.ispmanager.com` | Текущий сервер лицензирования ispmanager | [Инструкция о смене адреса сервера лицензий](https://www.ispmanager.ru/knowledge-base/kak-izmenit-server-licenzij) |
| `full:helpdesk.ispmanager.tech` | Тикеты и техподдержка ispmanager | [Раздел поддержки на российском сайте](https://www.ispmanager.ru/docs/ispmanager/ustanovka-ispmanager), [глобальный сайт](https://www.ispmanager.com/) |
| `domain:ascon.net` | Международный сайт АСКОН, академия КОМПАС-3D и документация C3D Viewer | [Подтверждение на ascon.ru](https://ascon.ru/news/2024/12/20/vyshel-kompas-3d-v23-na-anglijskom-yazyke/), [академия](https://ascon.net/online-academy/), [документация C3D Viewer](https://c3d.ascon.net/doc/viewer/install.html) |
| `domain:c3dlabs.com` | Сайт разработчика геометрического ядра C3D, дочерней компании АСКОН | [Страница команды АСКОН](https://ascon.ru/team/234/), [C3D Labs](https://c3dlabs.com/) |
| `domain:1ci.com` | Международное подразделение 1С и личный кабинет партнёров `my.1ci.com` | [Каталог 1С](https://1c.com/), [условия 1Ci](https://www.1ci.com/terms-of-use/) |
| `domain:infowatch.com` | Англоязычный каталог InfoWatch, в том числе Traffic Monitor | [Переключатель EN на infowatch.ru](https://www.infowatch.ru/o-kompanii-infowatch), [сайт продукта](https://infowatch.com/) |
| `full:ftp.altlinux.org` | Репозиторий пакетов, указанный по умолчанию в Альт Платформе 11 | [Настройка APT](https://docs.altlinux.org/ru-RU/platform/11.0/html/alt-platform/nastrojka_spiska_repozitoriev_apt.html) |
| `full:packages.altlinux.org` | Каталог пакетов Сизифа | [Описание проекта у Базальт СПО](https://www.basealt.ru/repository) |
| `full:docs.altlinux.org` | Официальная документация дистрибутивов Альт | [Портал документации](https://docs.altlinux.org/ru-RU/index.html) |
| `full:reg.trueconf.com` | Регистрация и проверка лицензии TrueConf Server Free | [Руководство администратора](https://trueconf.ru/docs/server/ru/admin/registration/), [назначение сетевых портов](https://trueconf.com/blog/knowledge-base/ports-trueconf-server-use) |
| `full:mirror.trueconf.com` | Сервер обновлений терминала TrueConf Group | [Руководство TrueConf Group](https://trueconf.ru/docs/group/ru/control-panel-settings/) |
| `full:packages.trueconf.com` | Второй сервер обновлений TrueConf Group | [Руководство TrueConf Group](https://trueconf.ru/docs/group/ru/control-panel-settings/) |
| `domain:arenadata.tech` | Основной сайт группы и каталог продуктов | [Сайт группы](https://arenadata.tech/ru), [согласие на обработку данных с указанием оператора сайта](https://arenadata.tech/ru/legal-information/privacy-agreement) |
| `full:hub.arenadata.io` | Официальный реестр контейнеров для установки ADCM | [Инструкция по установке ADCM](https://docs.arenadata.io/ru/ADCM/current/get-started/install.html) |
| `full:network.arenadata.io` | Портал загрузки пакетов развертывания Arenadata | [Ссылка «Скачать» на странице ADCM](https://arenadata.tech/ru/products/adcm) |
| `full:docs.arenadata.io` | Официальный портал документации Arenadata | [Ссылка «Документация» на странице ADCM](https://arenadata.tech/ru/products/adcm), [документация](https://docs.arenadata.io/ru/releases/index.html) |
| `full:registry.deckhouse.io` | Официальный реестр образов в международной инструкции Deckhouse Platform | [Установка из реестра .io](https://deckhouse.io/products/kubernetes-platform/documentation/v1/installing/), [параметры модуля на deckhouse.ru](https://deckhouse.ru/modules/deckhouse/configuration.html) |
| `domain:vtb.am` | Армянский сайт банка и документированный переход в интернет-банк `onlinebank.vtb.am`. Армянский регулятор указывает официальный домен, а отчёт банка за 2025 год называет ПАО Банк ВТБ единственным акционером | [Реестр ЦБ Армении](https://www.cba.am/en/licensed-banks), [отчёт за 2025 год](https://vtb.am/NewVersion/uploads/Reports/2025/PrimFS_4kv2025_rus.pdf), [официальный сайт](https://www.vtb.am/) |
| `domain:vtb.az` | Азербайджанский сайт, интернет-банк физлиц `online.vtb.az` и бизнеса `business.vtb.az`. Домен подтверждён регулятором, отчёт за 2025 год указывает долю ПАО Банк ВТБ 99,9999% | [Реестр ЦБ Азербайджана](https://www.cbar.az/page-195/banks?language=az), [отчёт за 2025 год](https://vtb.az/site/assets/files/9158/2025_annual_report.pdf), [официальный сайт](https://vtb.az/ru/) |
| `domain:moysklad.uz` | Узбекская витрина МоегоСклада и её поддомены, в том числе `events.moysklad.uz`. Оферта прямо указывает `moysklad.uz`, `moysklad.ru` и их поддомены. Предложение не подразумевает, что основной API переехал на .uz | [Витрина](https://www.moysklad.uz/), [оферта](https://events.moysklad.uz/upload/files/oferta_uz.pdf), [справочник API](https://dev.moysklad.ru/doc/api/remap/1.2/) |
| `domain:robokassa.com` | Основной сайт и публичные страницы подключения Робокассы. Платёжный хост `auth.robokassa.ru` уже покрыт, поэтому правило не добавляет покрытие существующей точки оплаты | [Техническая документация с прямой ссылкой и примером адреса оплаты](https://docs.robokassa.ru/ru/quick-start), [страница ООО «РОБОКАССА»](https://robokassa.com/about/) |
| `domain:mts.ai` | Официальный сайт и документация MWS AI, включая Cotype. Политика ООО «МВС ИИ» явно называет домен. Публичные API облачной платформы в `mwsapis.ru` уже покрыты | [Политика MWS AI](https://mts.ai/cookie-usage-policy/), [руководство Cotype](https://mts.ai/product/generative-ai-solutions/cotype-doc-admin/), [эндпоинты MWS](https://mws.ru/docs/cloud-platform/api/general/api-endpoints-and-url.html) |
