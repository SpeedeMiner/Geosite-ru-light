# GeoSite RU Light v11.12 — aviation and RUTUBE

Add ten exact hostnames. The eight aviation names were checked using
public GET requests from AS12389, AS3216 and AS207957. Domodedovo's
procurement portal was checked on both the homepage and the rules page.
The official RUTUBE News hostname returned a valid HTTPS redirect to
the separately verified RUTUBE homepage from the same three networks.

| Rule | Function |
|---|---|
| `full:aaq.aero` | Anapa Airport |
| `full:aer.aero` | Sochi Airport flight board |
| `full:ikar.aero` | Ikar check-in page |
| `full:krr.aero` | Krasnodar Airport |
| `full:market.dme.aero` | Domodedovo procurement platform |
| `full:mcx.aero` | Makhachkala Airport flight board |
| `full:rutube.news` | Official redirect to RUTUBE |
| `full:ticket.rusline.aero` | RusLine check-in page |
| `full:www.nbc.aero` | Begishevo Airport www host |
| `full:zia.aero` | Zhukovsky Airport flight board |

Measurements and exclusions are documented in the
[Domodedovo review](dme-market-routing.md),
[aviation and lib4u review](aviation-hosts-lib4u-audit.md), and
[RockBlack and RUTUBE review](rockblack-source-audit.md).
No imported routes or domains from either source, suffix expansions,
BLOCK changes, TLS store changes, or GeoIP changes.

Compared with v11.11, Light adds 10 RU rules and removes none (3,173 RU
rules, 44 BLOCK rules and 18 categories). Projecting the same DAT with
Server's existing policy adds the same 10 rules without loss (3,061 RU
rules in one category). The verified rollback baseline is v11.11.
