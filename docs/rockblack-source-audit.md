# RockBlack source review and RUTUBE redirect

Reviewed [RockBlack commit ea48594f](https://github.com/RockBlack-VPN/ip-address/tree/ea48594f9a3a9ab2df62d454f897b5f69c373ba2)
against numbered GeoSite Light and Server v11.11 and the [published
GeoIP snapshot 43421774698.1](https://github.com/SpeedeMiner/Geoip-ru-server/releases/tag/geoip-v41-snapshot-43421774698.1)
(SHA-256 `5e0e1f9fba8ad18b800e4cc6d255a7b94b6529a7426e6bafeba622aa0aa8b937`).

## GeoSite

The four explicit `RU-RU/*_domain` lists provide 720 unique hostnames, of
which 715 already match RU in both builds. None of the five uncovered
hosts qualifies for a routing change from this list:

- [`rutube.com`](https://api.globalping.io/v1/measurements/2LNcwOoYrx7UGaThG00021Uqv)
  serves a parking/for-sale page. [`rutube.net/lander`](https://api.globalping.io/v1/measurements/2J5RFt3GheF7Bskb300021Uqx)
  redirects to a GoDaddy sale page.
- `vkhost.github.io` is a GitHub Pages site. The same VK route file
  contains all four IPv4 /24s of the shared GitHub Pages /22.
- [`wildberries.md`](https://api.globalping.io/v1/measurements/2GUbC9DRsLkCMXb1F00021Uqv)
  did not resolve in any of the three probes. `api.vigo.one` lacks
  independent evidence of a required first-party RUTUBE function.
- RockBlack's `rockblack.dat` decodes as GeoSite for `CATEGORY-RU`.
  That category has 184 suffix rules. The sole difference from Light is
  the single-label suffix `psk`, which Server already has. Do not extend
  Light to that entire suffix based only on the source category.

Independent follow-up on the [official RUTUBE policy](https://rutube.ru/info/privacy_old/)
found `rutube.news` outside both v11.11 DATs. Its [HTTPS GET /](https://api.globalping.io/v1/measurements/21a5flqJ6phbl6XRu00021Uqw)
returned a validated TLS connection and a 301 redirect to `https://rutube.ru`
from AS12389, AS3216 and AS207957. The [destination](https://api.globalping.io/v1/measurements/2NMXYmtzaLwOwLr3E00021Uqw)
returned 200 with valid TLS in all three. Add only `full:rutube.news`.
`rutube.sport` is already covered. [`rutube.kids`](https://api.globalping.io/v1/measurements/2da8FZK8m2INpGxMH00021Uqw)
did not complete TLS. No BLOCK or release workflow changes.

## GeoIP

Parsed 653 IPv4 route rows from 64 `.bat` files under `RU-RU` without
executing them. Of 531 distinct CIDRs, 335 are completely present in the
published RU address set, 48 partially present and 148 entirely absent.
Deduplicated address space is 31,429,661 IPv4 addresses, of which 30,785,412
fall outside published RU. These are counts, not a recommendation to add
addresses. In particular:

| Route or gap | Evidence |
|---|---|
| `185.199.108.0/22` | Four /24s in the VK file, all absent in RU. [GitHub documents the Pages endpoints](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site). |
| `185.32.252.0/22` | Exact uncovered half of the VK file's /21. RIPE RIS lookup returned AS60277 for this half and AS47541 for the covered `185.32.248.0/22`. |
| `213.59.112.0/20` | Exact uncovered part of the Rostelecom file's /16. RIPE RDAP for its first /24 gives GLOBALTELEHOST, and published BGP data shows other origins within the /20. |
| `93.96.89.0/24` | In the Gosuslugi file. RIPE RIS returned covering `93.96.0.0/17`, AS5607 (Sky UK), not a first-party Gosuslugi network. |
| `104.16.0.0/12`, `57.0.0.0/8` | Broad routes in service files. The /12 alone spans more than a million IPv4 addresses and overlaps shared Cloudflare infrastructure. |
| `192.168.3.0/24` | Private address space present in the Wildberries file. |

Do not import the RockBlack routes or add them wholesale as exclusions.
`Global` is a separate routing-policy input, not evidence of ownership or
a feed of measured blocks. The active GeoIP snapshot is unchanged.
