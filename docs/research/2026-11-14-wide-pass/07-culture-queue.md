# Спорт, театры, образование и библиотеки

Сверка с опубликованными Light и Server v11.17. Две московские HTTP-пробы AS14576 и AS210644 нужны для расстановки приоритетов. Они не заменяют доверенный TLS и сверку сайта с оператором.

| Состояние | Хостов |
|---|---:|
| covered | 399 |
| no_http_code | 15 |
| priority_tls_operator | 12 |
| redirect_to_verify | 9 |
| probe_pending | 5 |
| excluded | 3 |
| needs_public_path | 2 |
| confirmed_exact | 1 |

## Хосты без полного покрытия двух опубликованных баз

| Имя | Источник | HTTP | Итог |
|---|---|---|---|
| `actopus.info` | [Театральная лаборатория "Акт.Опус"](https://reestr.stdrf.ru/reestr_list) | — | probe_pending  |
| `arctictheater.com` | [Арктический театр](https://reestr.stdrf.ru/reestr_list) | — | probe_pending  |
| `balashiha-dramteatr.bitrix24.site` | [Балашихинский драматический театр](https://reestr.stdrf.ru/reestr_list) | — | excluded хост на общей платформе, не расширять правило на корень |
| `baroquecompany.com` | [Театр Малый Трианон](https://reestr.stdrf.ru/reestr_list) | — | probe_pending  |
| `biathlonrus.com` | [Союз биатлонистов России](https://stm19.ru/sport/federationsrf) | — | confirmed_exact  |
| `cehtheatre.com` | [ЦЕХЪ](https://reestr.stdrf.ru/reestr_list) | — | probe_pending  |
| `comic-trust.com` | [Театральное товарищество "Комик-Трест"](https://reestr.stdrf.ru/reestr_list) | — | probe_pending  |
| `dlib.eastview.com` | [https://dlib.eastview.com/](https://uisi.ru/uisi/library/Poleznye_ssylki/ssylki.php) | — | excluded международный сервис East View, использовать только как ссылку на контент |
| `helisport.org` | [Федерация вертолётного спорта России](https://stm19.ru/sport/federationsrf) | [200 / 200](https://check-host.net/check-report/57bccdaek923) | priority_tls_operator  |
| `knam.online` | [Театр КнАМ](https://reestr.stdrf.ru/reestr_list) | [301 / 301](https://check-host.net/check-report/57bccda5kd0c) | redirect_to_verify  |
| `moscow-broadway.com` | [Театр МДМ-Московский дворец молодежи](https://reestr.stdrf.ru/reestr_list) | [302 / 302](https://check-host.net/check-report/57bccdb4ke4b) | redirect_to_verify  |
| `odnovremenno.com` | [Театральный проект Евгения Гришковца](https://reestr.stdrf.ru/reestr_list) | [200 / 200](https://check-host.net/check-report/57bccda9ke8) | priority_tls_operator  |
| `plastrain.com` | ["Пластилиновый дождь"](https://reestr.stdrf.ru/reestr_list) | [302 / 302](https://check-host.net/check-report/57bccd9ck15a) | redirect_to_verify  |
| `rusathletics.info` | [Всероссийская федерация лёгкой атлетики](https://stm19.ru/sport/federationsrf) | [200 / 200](https://check-host.net/check-report/57bccd9fke2e) | priority_tls_operator  |
| `russiansoftball.org` | [Федерация софтбола России](https://stm19.ru/sport/federationsrf) | [— / —](https://check-host.net/check-report/57bcce62kf2d) | no_http_code  |
| `sbiblio.com` | [http://sbiblio.com/biblio/](https://uisi.ru/uisi/library/Poleznye_ssylki/ssylki.php) | [200 / 200](https://check-host.net/check-report/57bcce5bk873) | priority_tls_operator  |
| `teatrodicapua.com` | ["Театр К" (Театро Ди Капуа)](https://reestr.stdrf.ru/reestr_list) | [200 / 200](https://check-host.net/check-report/57bcce48kaf6) | priority_tls_operator  |
| `theatreadliberum.com` | [Негосударственный авторский театр Республики Карелия "Ад ЛИБЕРУМ (Свободный)"](https://reestr.stdrf.ru/reestr_list) | [200 / 200](https://check-host.net/check-report/57bcce54kcda) | priority_tls_operator  |
| `transformatordoc.com` | [Трансформатор](https://reestr.stdrf.ru/reestr_list) | [— / —](https://check-host.net/check-report/57bcce3fkd75) | no_http_code  |
| `www.arlekiniada.com` | [Арлекиниада](https://reestr.stdrf.ru/reestr_list) | [— / —](https://check-host.net/check-report/57bcce38k8a0) | no_http_code  |
| `www.cardboardia.info` | [Картония](https://reestr.stdrf.ru/reestr_list) | [200 / 200](https://check-host.net/check-report/57bcceefk813) | priority_tls_operator  |
| `www.cogito-centre.com` | [Когито-Центр](https://gpa.cfuv.ru/ru/struktura/408-biblioteka/zakaz-uchebnoj-literatury/1641-veb-sajty-rossijskikh-izdatelstv) | [— / —](https://check-host.net/check-report/57bccefckc31) | no_http_code  |
| `www.cooperation-lab.com` | [Лаборатория молодых композиторов и драматургов"КоОПЕРАция"](https://reestr.stdrf.ru/reestr_list) | [301 / 301](https://check-host.net/check-report/57bccf0ak3b0) | redirect_to_verify  |
| `www.debufo.com` | [Театр в гриме De Bufo](https://reestr.stdrf.ru/reestr_list) | [— / —](https://check-host.net/check-report/57bccf04kf32) | no_http_code  |
| `www.eskizy.com` | [Авторский театр "Эскизы в пространстве"](https://reestr.stdrf.ru/reestr_list) | [— / —](https://check-host.net/check-report/57bccef8k40d) | no_http_code  |
| `www.fasrus.org` | [Федерация авиационного спорта России](https://stm19.ru/sport/federationsrf) | [— / —](https://check-host.net/check-report/57bccef2kcf0) | no_http_code  |
| `www.gold-theatre.com` | [Золотой театр](https://reestr.stdrf.ru/reestr_list) | [200 / 200](https://check-host.net/check-report/57bccf90k50b) | priority_tls_operator  |
| `www.gorodteatr.com` | [Самарский театр "Город"](https://reestr.stdrf.ru/reestr_list) | [— / —](https://check-host.net/check-report/57bccfa5k4d3) | no_http_code  |
| `www.hitrovka.com` | [Культурный центр "Хитровка"](https://reestr.stdrf.ru/reestr_list) | [301 / 301](https://check-host.net/check-report/57bccf96kdaf) | redirect_to_verify  |
| `www.kdteatr.net` | ["Камерный драматический театр" г.Тула](https://reestr.stdrf.ru/reestr_list) | [200 / 200](https://check-host.net/check-report/57bccf9fk442) | priority_tls_operator  |
| `www.komnata4.com` | [Комната4](https://reestr.stdrf.ru/reestr_list) | [— / —](https://check-host.net/check-report/57bccfa9k4c1) | no_http_code  |
| `www.mdtesenin.com` | [Московский Драматический Театр имени Сергея Есенина](https://reestr.stdrf.ru/reestr_list) | [404 / 404](https://check-host.net/check-report/57bccf9dk7f3) | needs_public_path  |
| `www.musical74.net` | [Театр мюзикла "Феерия"](https://reestr.stdrf.ru/reestr_list) | [— / —](https://check-host.net/check-report/57bcd02ak665) | no_http_code  |
| `www.novteatr.com` | [Новый театр](https://reestr.stdrf.ru/reestr_list) | [— / —](https://check-host.net/check-report/57bcd033k4b1) | no_http_code  |
| `www.polpred.com` | [https://www.polpred.com/](https://uisi.ru/uisi/library/Poleznye_ssylki/ssylki.php) | [200 / 200](https://check-host.net/check-report/57bcd035k221) | priority_tls_operator  |
| `www.pressreader.com` | [http://www.pressreader.com/](https://uisi.ru/uisi/library/Poleznye_ssylki/ssylki.php) | — | excluded международный сервис, доступ из вуза не означает принадлежность к RU/BY/KZ |
| `www.ruslanmalikov.com` | [МРМ](https://reestr.stdrf.ru/reestr_list) | [— / —](https://check-host.net/check-report/57bcd03ekae1) | no_http_code  |
| `www.rusmotorboat.com` | [Федерация водно-моторного спорта России](https://stm19.ru/sport/federationsrf) | [— / —](https://check-host.net/check-report/57bcd02fk8ff) | no_http_code  |
| `www.satbayev.university` | [Satbayev University](https://atuniversities.ru/en/membership/) | [301 / 301](https://check-host.net/check-report/57bcd026k4d8) | redirect_to_verify  |
| `www.stanislavsky-centre.com` | [«Московский Театральный Центр Станиславский»](https://reestr.stdrf.ru/reestr_list) | [404 / 404](https://check-host.net/check-report/57bcd0bekbef) | needs_public_path  |
| `www.stantsia.com` | [Арт-площадка СТАНЦИЯ](https://reestr.stdrf.ru/reestr_list) | [301 / 301](https://check-host.net/check-report/57bcd0b5k1de) | redirect_to_verify  |
| `www.teatr-k.com` | [Театральная компания Ковчег](https://reestr.stdrf.ru/reestr_list) | [— / —](https://check-host.net/check-report/57bcd0c1kd63) | no_http_code  |
| `www.teatrnakrishe.com` | [Театр на крыше](https://reestr.stdrf.ru/reestr_list) | [— / —](https://check-host.net/check-report/57bcd0bakd24) | no_http_code  |
| `www.trikst.com` | [Трикстер](https://reestr.stdrf.ru/reestr_list) | [301 / 301](https://check-host.net/check-report/57bcd0ack6a8) | redirect_to_verify  |
| `www.ugtu.net` | [Ukhta State Technical University](https://atuniversities.ru/en/membership/) | [200 / 200](https://check-host.net/check-report/57bcd13dk92c) | priority_tls_operator  |
| `www.volgatech.net` | [Volga State University of Technology](https://atuniversities.ru/en/membership/) | [200 / 200](https://check-host.net/check-report/57bcd132kf02) | priority_tls_operator  |
| `znanium.com` | [http://znanium.com/](https://uisi.ru/uisi/library/Poleznye_ssylki/ssylki.php) | [301 / 301](https://check-host.net/check-report/57bcd143k63a) | redirect_to_verify  |
