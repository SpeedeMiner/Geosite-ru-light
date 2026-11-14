# Безопасное возобновление трёх партий

Порядок и путь фиксированы в `01-plan.sha256sum`. Один внешний рабочий каталог на партию. Перед новым запуском сначала прочитать предыдущий архив и проверить текущий остаток квоты. Журнал коммитить и сверять с GitHub после каждой партии.

Из корня рабочей копии:

```sh
p=docs/research/2026-11-14-https-window5
runner=docs/research/2026-11-14-https-window3
python3 "$p/checkpoint.py" plan
```

Фактические минимумы остатка перед отправкой — 49 для первой партии (30 проб + 19 резерв) и 64 для каждой партии альтернатив (45 + 19). При наличии свежих результатов не запускать уже отправленную партию снова.

```sh
wave=first
python3 "$runner/probe-wave.py" "$p/01-wave-$wave.tsv" "$work/$wave" --workers 4 --reserve 19
python3 "$p/checkpoint.py" archive "$wave" "$work/$wave"
```

При обрыве сначала сверить `submitted.jsonl` с компактным журналом. Восстановить результат по сырому ответу или GET известного ID, не создавая нового измерения:

```sh
python3 "$runner/recover-wave.py" "$p/01-wave-$wave.tsv" "$work/$wave" --fetch > "$work/$wave/recovered.jsonl"
python3 "$p/checkpoint.py" archive "$wave" "$work/$wave"
```

`checkpoint.py` не допускает замену уже записанного архива. Сырые тела не коммитятся. В компактный архив входят ID, точный путь, три ASN, TLS/SAN, статусы и SHA-256 тел. Ревьюер сохраняет `<wave>-approvals.tsv` с полями `host`, `id`, `operator_url`, `rationale`, даже если нет допущенных имён (тогда только заголовок). `https_candidate` без явной записи остаётся `hold_review`.

```sh
python3 "$p/checkpoint.py" assemble first
python3 "$p/checkpoint.py" assemble first --check
python3 -m unittest discover -s "$p" -p 'test_*.py'
```

Для следующих стадий передавать последовательные префиксы `first fallback-a` и `first fallback-a fallback-b`. После любого изменения набора собрать Light/Server DAT и SRS, сверить точную дельту и только затем записывать итоговые числа. Исследовательский checkpoint не публикует релиз.
