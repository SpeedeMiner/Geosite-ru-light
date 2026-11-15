# Корпоративные платформы и публичные зависимости — 15 ноября 2026

Подтверждённые exact-кандидаты этой волны — `img.solarspace.pro`,
`cdn-viewer.diplodoc.com` и `perforator.tech`. Для трёх конкретных публичных изображений
совпал SHA-256 между рабочей выборкой и двумя российскими выходами на URL.
Это проверка нужного статического файла, а не проверка целого сервиса,
других ресурсов CDN, маршрутизации IP или его владельца.

- [Три точных имени](verified-three.txt), [57 накопленных](stacked-fifty-seven.txt),
  [полный replay +57](full-build-replay-fiftyseven.tsv),
  [ранний пакет +56](stacked-fifty-six.txt),
  [полный replay +56 на v11.19 и кандидате v11.20](full-build-replay-fiftysix.tsv),
  [отдельный replay +2](full-build-replay-two.tsv).
- [Сводка](summary.json). Каталоги
  [01](catalog-coverage-01.tsv), [02](catalog-coverage-02.tsv),
  [03](catalog-coverage-03.tsv), [04](catalog-coverage-04.tsv),
  [05](catalog-coverage-05.tsv), [06](catalog-coverage-06.tsv).
- [Квитанции источников 01](source-receipts-01.tsv) и [02](source-receipts-02.tsv).
  Рабочие HTTP 200 с challenge или прокси-заглушкой исключены
  из числа пригодных исходных URL.
- [VK Cloud и Wildberries — точный разбор источников](structured-hosts.tsv),
  [регионы и отдельно сверенные официальные адреса](manual-source-coverage.tsv).
  Точки публичной авторизации, указанные в документации, сверены по базе,
  вход и вызовы API не выполнялись.
- [DNS](dns.tsv), [BGP origin](bgp.tsv), [GET из рабочей среды](workspace-https.tsv),
  [сверка с закреплённым GeoIP](geoip-crosscheck.tsv).
- VPNObratno: [первая таблица](vpn-43730220559.tsv)
  ([квитанция](vpn-43730220559-receipt.json)),
  [вторая](vpn-43730579689.tsv) ([квитанция](vpn-43730579689-receipt.json)),
  [третья](vpn-43731073439.tsv) ([квитанция](vpn-43731073439-receipt.json)),
  [четвёртая](vpn-43731303839.tsv) ([квитанция](vpn-43731303839-receipt.json)),
  [пятая](vpn-43731703539.tsv) ([квитанция](vpn-43731703539-receipt.json)).
  Ноль запросов Globalping, в основном счётчике RU эти замеры не засчитываются.
- `yaff.tech` официально связан с проектом Яндекса, но четыре попытки
  на двух URL завершились по таймауту. Наблюдение не доказывает блокировку.
  Проект уже доступен как репозиторий GitHub, соответствующая категория
  не меняется.

НСПК: с отдельным проверенным корнем TLS прошёл по обоим .com, но HTML
не подтвердился (403 из двух выходов). СБП дал 200 со штатным набором CA.
[Объём доверия и результаты](nspk-trust-scope.tsv).

Perforator: подтверждён ожидаемый HTML из AS8369 и AS44724.
[DNS и BGP отдельно](perforator-dns-bgp.tsv).

Файлы находятся в исследовательской ветке, не в сборке релиза или CDN.
