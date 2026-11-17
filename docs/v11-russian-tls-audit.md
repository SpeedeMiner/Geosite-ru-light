# Проверка российского TLS в аудите GeoSite

Предыдущие замеры v11.9–v11.11 использовали результат `tls.authorized` штатного
[HTTPS-проба Globalping](https://github.com/jsdelivr/globalping-probe/blob/master/src/command/handlers/http/undici.ts).
Тот фиксирует результат валидации Node.js, но отдельно не подгружает корень
Минцифры. HTTP 200 при `tls.authorized=false` подтверждает, что проб получил
ответ, но не подтверждает подлинность сайта и не означает блокировку ресурса.
Сборка DAT не проверяет TLS при выборе маршрута. TLS здесь — сигнал качества
при аудите кандидатов.

## Контроль 13 ноября 2026 года

Российские точки в сетях AS12389, AS3216 и AS207957.

| Хост | Что увидели пробы | Решение |
|---|---|---|
| `www.sberbank.ru` | 3/3 HTTP 200, нужное имя в SAN, issuer `Russian Trusted Sub CA`, `SELF_SIGNED_CERT_IN_CHAIN`. [Замер](https://api.globalping.io/v1/measurements/2I6E0m0tfOJWpohfa00021Uq9) | Контроль для отдельной проверки доверия. Для криптографического подтверждения серверного сертификата нужен PEM, а не только поле issuer. |
| `www.gosuslugi.ru` | 3/3 HTTP 200 и успешная TLS-проверка с GlobalSign. [Замер](https://api.globalping.io/v1/measurements/2nt7qLhiAwUM6OZg600021Uq9) | Контроль, прошедший штатную проверку. Не обобщать на другие домены и точки. |
| `dme.aero`, `www.dme.aero` | GlobalSign, SAN для `dme.ru` и его поддоменов, ни одного нужного имени `.aero`. [dme.aero](https://api.globalping.io/v1/measurements/2Vf8FdtGoY7nIU1Vb00021Uq0) · [www.dme.aero](https://api.globalping.io/v1/measurements/2Q6AN3zZ4iUN3wlyI00021Uq0) | HOLD, ошибка имени. Проверенные адреса — [dme.ru](https://api.globalping.io/v1/measurements/2YuJKzT02UkzNjcFA00021Uq9) и [www.dme.ru](https://api.globalping.io/v1/measurements/2rOIpKq7KmUMCpIfj00021Uq9), оба 3/3 HTTP 200 с валидным TLS. |
| `app.payinrussia.com` | 3/3 HTTP 200, SAN совпал по `*.payinrussia.com`, issuer GlobalSign, `UNABLE_TO_VERIFY_LEAF_SIGNATURE`. [Замер](https://api.globalping.io/v1/measurements/2qMkOny6LIQs6e9oZ00021Uq0) | HOLD до проверки цепочки, отданной сервером. Ошибка не доказывает, что сервер пропустил конкретный intermediate. |

## Порядок перепроверки

1. С доверенной точки в РФ сохранить выданную сервером цепочку с правильным SNI
   в PEM, листовым сертификатом вперёд. Записать время, IP, ASN и SHA-256
   листового сертификата. Снимок цепочки сам по себе не является успешным TLS.
2. Взять RSA root и intermediate с [Госуслуг](https://www.gosuslugi.ru/crt).
   Инструмент сверяет SHA-256 этих двух сертификатов с известными отпечатками.
   При ротации сначала обновить отпечатки по проверенному официальному источнику.
   Указывать отдельно публичный CA-bundle без локально добавленного российского
   корня. Ничего не добавлять в системное хранилище.
3. Проверить SAN, срок действия, назначение серверного сертификата и подписи
   отдельно по публичному набору УЦ и по RSA-корню Минцифры.

```sh
python3 tools/verify_service_tls.py www.sberbank.ru \
  --chain peer.pem \
  --expected-leaf-sha256 "$LEAF_SHA256_FROM_MEASUREMENT" \
  --public-ca-file public-ca-bundle.pem \
  --ru-root russian_trusted_root_ca.pem \
  --ru-intermediate russian_trusted_sub_ca.pem
```

Нужен OpenSSL 3. Если CA-файл скачан в формате DER, сначала преобразовать его
через `openssl x509 -inform DER -in certificate.cer -out certificate.pem`.
Если файл уже PEM, преобразование не нужно. Опциональный intermediate подаётся
как часть цепочки, а не как доверенный корень. Успех только с этим дополнением
получает отдельный результат `russian_trusted_rsa_needs_intermediate` и ненулевой
код завершения. Профили ГОСТ, приватные УЦ и отзыв сертификатов этот режим
не проверяет. Он также не воспроизводит TLS-настройки конкретного браузера.

Для кандидата требуется отдельное подтверждение принадлежности сервису
и доступности нужного пути из российских сетей. Результаты перепроверки
не добавляют правила автоматически и не меняют RU, BLOCK или профиль Happ.
