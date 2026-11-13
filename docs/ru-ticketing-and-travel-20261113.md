# Russian ticketing and travel after v11.14

The proposed hostnames did not match any RU or BLOCK rule in the published
Light v11.14 DAT or any RU rule in the Server v11.14 DAT. Each rule is exact.
Requests were anonymous HTTPS GETs from AS12389, AS3216 and AS207957, in
that order. HTTP codes in the proposal table require authenticated TLS
and a matching hostname. No booking, account access or payment was attempted.

| Exact host | Service and source | Path and results |
|---|---|---|
| `chip.travel` | [Russian travel booking service](https://chip.travel/doc/chip_agreement.pdf) | [`/` · TLS timeout / 200 / 200](https://api.globalping.io/v1/measurements/2LOipWPsurowP7y9h00021Usx) |
| `travelata.com` | [Travelata alias redirects to `travelata.ru`](https://domainnamewire.com/2026/09/30/this-weeks-sedo-end-user-domain-name-sales/) | [`/` · 301 / 301 / 301](https://api.globalping.io/v1/measurements/2gdZIpVDS5r09WZYK00021Usw) |
| `tury.travel` | [Anex Russian travel agency site](https://tury.travel/) | [`/` · 200 / 200 / 200](https://api.globalping.io/v1/measurements/2rlrAKU0z7fZuUDn500021Usx) |
| `ufs.travel` | [UFS alias redirects to `www.ufs-online.ru`](https://zhd.ufs-online.ru/de/) | [`/` · TLS timeout / 301 / 301](https://api.globalping.io/v1/measurements/2Q8dF9azbi8jb9EBZ00021Usw) |
| `www.ufs.travel` | [UFS www alias redirects to `www.ufs-online.ru`](https://www.ufs-online.ru/o-kompanii) | [`/` · 301 / 301 / 301](https://api.globalping.io/v1/measurements/22kiAmYEaiO7NRHJB00021Usw) |
| `www.unitiki.com` | [Unitiki alias redirects to `unitiki.com`](https://unitiki.com/policy) | [`/contacts` · 301 / 301 / 301](https://api.globalping.io/v1/measurements/2vdu0I4YWEhhVq0VQ00021Usw) |

`travelata.ru` and `www.ufs-online.ru` already match the RU suffix.
`unitiki.com` already has an exact rule. The official
[Unitiki contact page](https://api.globalping.io/v1/measurements/24LSTwHKBxF3zi8yk00021Usw) and
[UFS company page](https://api.globalping.io/v1/measurements/2Yo51uUvoyQvI8OIM00021Usw) both returned
verified HTTPS 200 from all three ASNs.

## Not added

- [`www.chip.travel`](https://api.globalping.io/v1/measurements/2UeNKNnvDGmlhq5iZ00021Usx) produced a
  timeout on AS12389 and a 301 on the other two with
  `ERR_TLS_CERT_ALTNAME_INVALID`. The certificate names `chip.travel`,
  not the www host. An HTTP redirect does not cure a TLS hostname mismatch.
- [`fstravel.com`](https://api.globalping.io/v1/measurements/2tKxYmzG2LIbx4u3500021Usw) had TLS on all
  three probes but returned 403 on the homepage. The
  [agent page](https://api.globalping.io/v1/measurements/2bgTFCaEU9hSGg1pz00021Usw) and
  [aviation site](https://api.globalping.io/v1/measurements/24neDRA5oOHxTR9Z600021Usx) each returned 200 from
  only one ASN. This is inconclusive, not a nationwide blocking claim.
- [`www.anextour.com`](https://api.globalping.io/v1/measurements/27IfhSDb3lx9VN3Z300021Usx) sent
  AS12389 to the Polish site and the other two to the Russian site.
  [`anextour.com`](https://api.globalping.io/v1/measurements/2FWKs7Z51wTQwRKFM00021Usx) sent all three to
  `anextour.ru` from different edges. Hold the shared brand hosts. The
  Russian destination already matches the RU suffix.
- [`www.tez-tour.com`](https://api.globalping.io/v1/measurements/2GbYnj76MleEOFW0P00021Usx) and
  [`tourist.tez-tour.com`](https://api.globalping.io/v1/measurements/2Co9u1EFkb2Nc8R4d00021Usx) responded
  on all probes, but the public contacts identify the international
  operator. A Russian-specific host was not established.
- [`busfor.com`](https://api.globalping.io/v1/measurements/2dLCOkMq4GbxWdauW00021Usw) redirected to
  global BlaBlaCar on one network and returned 403 on the other two.
  `busfor.ru` already matches the RU suffix.
- [`ostrovok.com`](https://api.globalping.io/v1/measurements/2quoWRfed1Vdh7Yay00021Usw) refused TCP/443
  in all three networks. The documented Russian service is `ostrovok.ru`.
- [`www.bgoperator.com`](https://api.globalping.io/v1/measurements/2Sqr5LPIg7qzjoTuw00021Usx) did not
  reach HTTP in any probe. `bgoperator.ru` is already covered.
- No changes to hosts already covered by the `onetwotrip.com`,
  `level.travel`, `bronevik.com`, `101hotels.com`, or `.ru` suffixes.

No changes to BLOCK, GeoIP, or external source pins.
