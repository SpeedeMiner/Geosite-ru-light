# GeoSite RU Light v11.7 — exact vendor infrastructure hosts

Add four exact rules to `RU`. No new suffix rules or policy changes.

| Host | Why it belongs in RU | First-party evidence |
| --- | --- | --- |
| `86.license5.ispsystem.com` | Documented ISPsystem 5.x license service and an ispmanager license diagnostic endpoint | [ISPsystem license troubleshooting](https://www.ispsystem.com/docs/coremanager/knowledge-base/troubleshooting/license-activation-issues), [ispmanager license diagnostics](https://www.ispmanager.com/knowledge-base/panel-does-not-activating-due-to-license-server-unavailablity) |
| `hub.adsw.io` | Docker registry named as the default for an online Arenadata Hyperwave installation via ADCM | [Arenadata online cluster configuration](https://docs.arenadata.io/ru/ADH/current/get-started/online_install/adh-install/config-cluster.html), [Arenadata ADCM source](https://github.com/arenadata/adcm) |
| `license5.ispsystem.com` | Documented ISPsystem 5.x license service | [ISPsystem license troubleshooting](https://www.ispsystem.com/docs/coremanager/knowledge-base/troubleshooting/license-activation-issues), [BILLmanager 5 activation](https://www.ispsystem.com/docs/billmanager/knowledge-base/troubleshooting-guide/if-the-activation-failed) |
| `metricreport.ispsystem.net` | Metrics endpoint listed among required resources for VMmanager 6 and DCImanager 6 | [VMmanager 6 requirements](https://www.ispsystem.ru/docs/vmmanager-admin/o-platforme/trebovaniya-k-serveru-v2026091-7), [DCImanager 6 requirements](https://www.ispsystem.ru/docs/dcimanager-admin/o-platforme/trebovaniya-k-serveru-v2026111) |

Vendor documentation establishes the service role. It does not prove live
reachability in every network. Older licensing endpoints are listed separately
from the already-covered current license hosts. No generic registry, external
CDN, or unrelated tracking host is added.

Existing TrueConf registration and update hosts, Deckhouse's
`registry.deckhouse.io`, and the documented current ispmanager package
and license hosts are already covered in v11.6. No other TrueConf or
Deckhouse host in this pass had comparable evidence for a distinct missing
service endpoint. The corporate discovery report from the PR #16 run had
31 uncovered, weak external dependencies and no prioritized candidate.
The four additions here come from direct review of vendor documentation.

Against published v11.6, Light has **3,096 RU rules (+4, −0)** and
**18 categories**. BLOCK and all 16 Hydra categories are unchanged.
The DAT is **83,200 bytes** with SHA-256
`b51429c5277c75cd40f889eeb8786937ac5f2df236764c0f60b7a700344879db`.

The unchanged Server projector, using the current Server policy and v11.6
as its previous DAT, produces one `RU` category with **2,984 rules (+4, −0)**
and 33 exact names. The projected Server DAT SHA-256 is
`8dde90416e349c4c841d580f6c00506c2e5e91d7314da654dc841dc4724499c4`.
This is a local projection, not a Server release.
