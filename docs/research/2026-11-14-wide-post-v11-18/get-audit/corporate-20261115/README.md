# Корпоративный аудит GeoSite — 15 ноября 2026

Базовая сверка проведена с опубликованными Light/Server v11.19. В отдельном
локальном сравнении использован кандидат v11.20 из PR №39. Это аудит,
не обновление main или правил выпуска.

- [Банки и реестр сайтов ЦБ](cbr-summary.json) · [приоритетная матрица](cbr-priority.tsv) · [исторические адреса](cbr-gaps.tsv).
- [Технические хосты банков и облаков](curated-coverage.tsv) · [DNS/ASN](asn-attribution.tsv) · [источники](source-results.tsv).
- [VPN GET и TLS](vpn-43714186452.tsv) · [квитанция](vpn-43714186452-receipt.json) · [решения](candidate-decisions.tsv).
- [Два точных кандидата TData](tdata-exact-candidates.txt) · [проверка сборки](tdata-preview.tsv).
- [Платёжные системы](payment-active-coverage.tsv) · [ранее проверенные, но не выпущенные](payment-reviewed-six.tsv) · [отложенные](payment-unreleased-review.tsv).

В первую очередь продолжать с двух точных хостов TData. Пакет Sendy,
UnitedBanks и HelloPay сверить с прежними решениями для корня и WWW,
не расширяя на суффикс. Legacy-алиасы без DNS/HTTPS и международный
`www.unionpayintl.com` не включать по одному факту присутствия в реестре.
ASN назначения, российский ASN наблюдения и владение доменом —
разные виды доказательств.
