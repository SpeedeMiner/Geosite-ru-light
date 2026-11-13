# GeoSite RU Light v11.16 — 15 verified service hostnames

This release adds exact RU rules for Pachca, Docsvision, Sign.Me, CDNvideo's documented dashboard and docs, Pruffme, Novofon, and Arenadata Catalog.

[First-party sources and HTTPS measurements](https://github.com/SpeedeMiner/Geosite-ru-light/blob/main/docs/ru-services-wide-review-20261113.md) cover every added hostname across AS12389, AS3216 and AS207957. Pachca's API returned its expected unauthenticated 401. The Docsvision www alias returned a 301 to the verified canonical host.

Light has 3,206 RU rules (+15, −0) and 44 unchanged BLOCK rules. No other categories, upstream input pins or GeoIP data changed. The rollback baseline is v11.15.
