# Сквозная проверка +372 / −0

Штатная сборка и независимый replay из опубликованных DAT v11.17 дали попарно одинаковые байты Light и Server. Light — 4 218 RU, 44 BLOCK и 16 других категорий. Server — 4 106 правил и только RU. По всем 17 категориям вне RU совпали байты SRS, в том числе BLOCK. Все 18 SRS прошли сверку после декомпиляции. 1 116 проверок матчера выполнены в sing-box 1.13.12. Загрузка RU/BLOCK отдельно проверена в 1.8.14 и 1.13.12.

| Артефакт | SHA-256 |
|---|---|
| Список правил | `f47b1ea0ff74bfefe53ac99119dc259c594aed37a2f369d225d901e2d5ae48ad` |
| Light DAT | `5ec03b7d99e2468c0e4e1fb59ecf92d148ae31167090b997dd5773780746f926` |
| Server DAT | `02233c1c5f0c68144580a62bc8b852a2b4a420455ea50b90e6b36e52391057a7` |
| RU SRS | `26c2f5640cdf78e7585d7afe270ff6582d306ea0414fe75ce451f80db2636f4b` |
| Офлайн-квитанция | `9bdbe605c0b89122ac4ed0f7eda3595a73e8044be8f56470e6faae6d31bca2b2` |

Восстановлены все пять основных файлов, сверены пять файлов отката v11.17, локальная проверка квитанции прошла. `v11.18` — тестовый аргумент, не тег. Main, release, опубликованные наборы и GeoIP не менялись. Журнал воспроизводится командой ниже без запросов.

```sh
p=docs/research/2026-11-14-https-window7
python3 -B "$p/checkpoint.py" assemble inherited sector regional extra archive --check
python3 -B -m unittest discover -s "$p" -p 'test_checkpoint.py'
```
