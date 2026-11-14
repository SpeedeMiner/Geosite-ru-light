# GeoSite RU Light

Готовая клиентская база доменных правил. Для Xray/V2Ray используйте
[`geosite_RU.dat`](https://github.com/SpeedeMiner/Geosite-ru-light/releases/latest/download/geosite_RU.dat).

## sing-box

В [последнем релизе](https://github.com/SpeedeMiner/Geosite-ru-light/releases/latest)
и ветке `release` публикуется отдельный бинарный rule-set для каждой категории DAT.

| Категория | Файл |
| --- | --- |
| `RU` | [geosite_RU.srs](https://raw.githubusercontent.com/SpeedeMiner/Geosite-ru-light/release/geosite_RU.srs) |
| `BLOCK` | [geosite_BLOCK.srs](https://raw.githubusercontent.com/SpeedeMiner/Geosite-ru-light/release/geosite_BLOCK.srs) |
| Категории Hydra, например `GOOGLE-DEEPMIND`, `GOOGLE-PLAY`, `YOUTUBE` | [Все наборы](https://github.com/SpeedeMiner/Geosite-ru-light/tree/release) |

[SHA-256 для всех .srs](https://raw.githubusercontent.com/SpeedeMiner/Geosite-ru-light/release/geosite_srs.sha256sum).
Публикуется бинарный формат v1. Точные правила DAT становятся `domain`,
а правила для домена и его поддоменов становятся `domain_suffix`. Сами
наборы не задают `DIRECT`, `PROXY` или блокировку.

Пример элемента массива `route.rule_set`:

```json
{
  "type": "remote",
  "tag": "geosite-ru",
  "format": "binary",
  "url": "https://raw.githubusercontent.com/SpeedeMiner/Geosite-ru-light/release/geosite_RU.srs"
}
```

Укажите тег в `route.rules[].rule_set` и назначьте нужное действие. Если
используете `BLOCK` и отдельные проксируемые категории как исключения из
`RU`, расположите их правила раньше `RU`.

### Повторная сборка из DAT

На Linux x86-64 из корня репозитория, с пустой папкой для результата:

```sh
bash tools/build_geosite_srs.sh --dat /path/to/geosite_RU.dat --output-dir srs
(cd srs && sha256sum --check --strict geosite_srs.sha256sum)
```

Сборка фиксирует версию компилятора и проверяет его SHA-256. Каждый набор
проверяется декомпиляцией и сравнением точных правил и суффиксов с исходным DAT.
