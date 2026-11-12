# v11.1 candidate — critical CDN / corporate roots and safe update logic

Date: 2026-11-12. Base: published immutable `v11`, commit `e35af942d664de202a4958835ca6dd5652f9fc6d`.
Pull request: https://github.com/SpeedeMiner/Geosite-ru-light/pull/3

## Input archive vs GitHub head

Uploaded reference: `Geosite-ru-light-main_v11_improved.zip`.

**Not applied verbatim.** The archive was built from an earlier main snapshot, before the immutable `v11` tag and rolling `latest-optimized` tag safety fixes were merged in PR #2. Blindly replacing its `.github/workflows/blank.yml` or `tools/geosite-delta` would revert released behavior.

The archive lists 59 pinned rules (30 from v11 and 29 proposed). Of these, **25 newly proposed roots are pinned** in the current PR, bringing `data/v11-approved-effective-ru.txt` to **55**. Four require stronger evidence and were **not** imported:

| Domain | Decision | Reason |
| --- | --- | --- |
| `ozon.am` | hold; not DIRECT | Ozon confirms shipments to Armenia, but this does not establish ownership or use of this **specific apex**. Official Ozon link: https://docs.ozon.ru/common/dostavka/dostavka-za-predely-rossii/?country=ARM |
| `ozon.kg` | hold; not DIRECT | Ozon confirms shipments to Kyrgyzstan from `ozon.ru`; no first-party proof for `ozon.kg`. |
| `servicepipe.io` | hold; not DIRECT | Russian company official site is `https://servicepipe.ru/`; the domain `servicepipe.io` was not established as a first-party endpoint. |
| `selectel.org` | hold; not DIRECT | Current upstream `v2fly/data/selectel` lists `selectel.com`, `selectel.info`, `selectel.io` etc., but not `selectel.org`; ownership/use needs verification. |

## Confirmed or strongly supported pinning

Newly pinned, suffix-scoped domains:

- Avito/Habr: `avito.st`, `habrastorage.org`. Primary Habr source: https://habr.com/ru/articles/103146/ ; Avito `pic1.avito.st` independently documented, not a guarantee of ownership of all future subdomains.
- Yandex: `yandexcloud.net`, `yadi.sk`, `ya.cc`, `naydex.net`. Bucket scheme: https://yandex.cloud/ru/docs/storage/concepts/bucket ; upstream `v2fly/data/yandex` contains `naydex.net`, `ya.cc`, `yadi.sk`. Yandex OV TLS certificate with `naydex.net`: https://radar.cloudflare.com/ru-ru/domains/domain/naydex.net
- VK: `vkuser.net`, `vkuseraudio.net`, `vkuservideo.net`, `vkuserlive.com`, `vk-cdn.net`, `vk-portal.net`, `mvk.com` (in `v2fly/data/vk`): https://github.com/v2fly/domain-list-community/blob/master/data/vk
- Tilda: `tildacdn.com`, `tilda.ws`, `tilda.cc`, `tildaapi.com`, all in `v2fly/data/tilda`; docs: https://help-ru.tilda.cc/settings
- Beget: `beget.com`, `beget.tech` (in `v2fly/data/beget`): https://github.com/v2fly/domain-list-community/blob/master/data/beget
- StormWall: `stormwall.pro`, official https://stormwall.pro/
- 1C: `1cfresh.com`, official https://www.1cfresh.com/about
- Wildberries: `wildberries.am`, `wildberries.uz`, `wildberries.kg`, upstream `v2fly/data/wildberries`; official storefronts https://www.wildberries.am/ and https://www.wildberries.uz/
- Ozon: `ozon.uz`, official https://www.ozon.uz/seller/ozon/ ; https://docs.ozon.kz/legal/terms-of-use/site/content-policy/

**Caveat:** shared services such as Yandex Cloud Object Storage, Tilda or anti-DDoS providers host third-party content. Pinning the operator domain routes the shared infrastructure directly, including potential foreign customer assets; it does not prove individual customer ownership.

## v2fly category inventory, upstream 2026-11-12

Checked suggested standalone names against actual `v2fly/domain-list-community/data/`:

- Found: `habr`, `mvideo`; `habr` imported because it explicitly contains `habrastorage.org` and `habr.com` verified.
- `mvideo` deliberately deferred: includes `acmvid.com` and a `Full`-scoped foreign-vendor endpoint `mvideo.edna.io`, which cannot safely become a global suffix without owner and scope evidence.
- Not present as named independent data files at the time of check: `ivi`, `premier`, `start`, `amediateka`, `litres`, `pikabu`, `cyberleninka`, `lesta`, `astrum`, `vkplay`, `mir`, `nspk`, `gosuslugi`, `pochta`, `rzd`, `aeroflot`, `s7`, `lamoda`, `dns-shop`, `citilink`, `eldorado`, `kuper`, `samokat`, `category-gov-by`, `category-gov-kz`, `kaspi`, `kolesa`.
- `4pda` intentionally **not** imported. Explicit user requirement: neither `4pda.to` nor its descendants may appear in `geosite:RU`.

## Parser and build fixes

1. `import_corporate_category`: allow suffix tokens without attributes or with **only** `@ru` attributes. All `@ads`, `@!ru`, `@cn`, `@telemetry`, `full:`, `regexp:` and `keyword:` remain excluded. Inline assertions test both positive and negative examples.
2. Added Unicode labels `бел`, `қаз` to `russianTLDLabels`. Go unit tests cover U-label and ACE versions.
3. Main DAT-source loop and text positive-extra loop now use `addPositiveRule`, so a vendor endpoint `prod.ntprog.com` remains `Full`, not `RootDomain`. The exact-host verifier still checks all four vendor hosts. Unit test covers the case where source lists also contain them.
4. The semantic delta checks all **new** effective RU rules against the pinned manifest, but also checks that all **old** pinned rules remain covered by the candidate regardless of whether they are already in rolling `latest-optimized`. It therefore handles a baseline already containing v11, unlike a strict 30-rule transitional delta.
5. Unreviewed future upstream additions remain **fail-closed**: the scheduled `main` rebuild cannot auto-publish a newly introduced foreign domain just because a third-party list suggested it. On failure, `geosite-ru-main-blocked-update-review` stores the DAT and delta for review (14 days). Safe weekly re-synchronization of unchanged effective RU works without needing the old 30-rule delta.

## Verified PR CI

https://github.com/SpeedeMiner/Geosite-ru-light/actions/runs/43277381905

- RU **3051**, BLOCK **43**, DAT **82206 bytes**.
- Effective delta against published v11: **RU +2 (`ozon.uz`, `stormwall.pro`), RU lost 0, BLOCK +0/-0**.
- All **55** pinned rules remain effectively covered (some by v11 or upstream already).
- `4pda.to` remains outside DIRECT. Two-stage Go tests and comparison pass.

## Release status

This is a **Draft PR**, not a production release. Latest published immutable `v11` and rolling `latest-optimized` remain unchanged. Do not deploy the uploaded archive directly or present `v11.1` as published before merged production CI and digest verification.
