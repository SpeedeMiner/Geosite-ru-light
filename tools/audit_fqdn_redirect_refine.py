#!/usr/bin/env python3
"""Recognize verified same-registrable-domain HTTPS redirect chains from RU evidence."""
import collections,csv,json,shutil
from pathlib import Path
from urllib.parse import urlsplit
from publicsuffix2 import get_sld

def ru_redirect_works(host,o):
    e=o.get("evidence") or {}
    if o.get("vpn_country")!="RU" or o.get("asn_conflict") is not False or o.get("verified_by_sources",0)<2:
        return False
    hops=e.get("hops") or []
    if e.get("reason")!="redirect; inspect destination" or len(hops)<2: return False
    try:
        suffix=get_sld(host,strict=True)
        if not suffix: return False
        for h in hops:
            u=urlsplit(h.get("url",""))
            if u.scheme!="https" or not u.hostname or get_sld(u.hostname,strict=True)!=suffix or h.get("tls")!="valid": return False
        return 200<=int(hops[-1].get("status",0))<300
    except (TypeError,ValueError): return False

# Tests include cross-site, certificate failure, and untrusted exit.
base={"vpn_country":"RU","asn_conflict":False,"verified_by_sources":2,
      "evidence":{"reason":"redirect; inspect destination","hops":[
      {"url":"https://example.com/","tls":"valid","status":301},
      {"url":"https://www.example.com/","tls":"valid","status":200}]}}
assert ru_redirect_works("example.com",base)
import copy
x=copy.deepcopy(base);x["evidence"]["hops"][-1]["url"]="https://unrelated.org/";assert not ru_redirect_works("example.com",x)
x=copy.deepcopy(base);x["evidence"]["hops"][-1]["tls"]="certificate_error";assert not ru_redirect_works("example.com",x)
x=copy.deepcopy(base);x["verified_by_sources"]=1;assert not ru_redirect_works("example.com",x)
x=copy.deepcopy(base);x["evidence"]["hops"][-1]["status"]=403;assert not ru_redirect_works("example.com",x)

src=Path("first");out=Path("refined");shutil.copytree(src,out,dirs_exist_ok=True)
original=json.loads(Path("preserved/report.json").read_text(encoding="utf-8"))["hosts"]
with (src/"classification.csv").open(encoding="utf-8",newline="") as f: rows=list(csv.DictReader(f))
if len(rows)!=4495 or {r["hostname"] for r in rows}!=set(original): raise SystemExit("host set mismatch")
changed=[]
for row in rows:
    host=row["hostname"]
    if row["category"]!="UNKNOWN":continue
    item=original[host]
    valid=[o for o in item.get("baseline",[])+item.get("targeted",[]) if ru_redirect_works(host,o)]
    if valid:
        row["category"]="ALIVE"
        row["reason"]="RU VPN: HTTPS redirect within registrable domain; valid TLS on each hop and final HTTP 2xx; ASNs "+",".join(sorted({str(o.get("vpn_asn")) for o in valid}))+". Content and full application function not independently guaranteed."
        changed.append(host)
categories={k:[] for k in ("ALIVE","INFRASTRUCTURE","GEO_BLOCKED","PARKED","EXPIRED","DEAD","UNKNOWN")}
for r in rows: categories[r["category"]].append(r["hostname"])
if sum(map(len,categories.values()))!=4495: raise SystemExit("category count mismatch")
with (out/"classification.csv").open("w",encoding="utf-8",newline="") as f:
    w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
for k,v in categories.items(): (out/(k+".txt")).write_text("\n".join(v)+("\n" if v else ""),encoding="utf-8")
summary=json.loads((out/"summary.json").read_text(encoding="utf-8"))
summary["categories"]={k:{"count":len(v),"percent":round(len(v)*100/4495,2)} for k,v in categories.items()}
summary["verified_same_domain_redirects_promoted"]=len(changed)
summary["method"]="Only verified HTTPS 2xx chains confined to same registrable domain; no content functionality assertion."
(out/"summary.json").write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding="utf-8")
lines=["# RU FQDN classification","", "| Category | Count | Percent |","|---|---:|---:|"]
for k,v in summary["categories"].items(): lines.append(f"| {k} | {v['count']} | {v['percent']:.2f}% |")
lines+=["",f"Same-registrable-domain verified HTTPS redirects newly recognized: {len(changed)}.","",
"Detailed FQDN reasons: classification.csv. External DNS, HTTP, HTTPS and registration evidence: diagnostics.json and registration.json. Original 14,350 observations are preserved separately.",
"RU exit attribution is historical and lacks independent packet capture. A 2xx response does not prove full application functionality. RDAP 429 is a rate limit, not expiry. Zero categories represent no confirmed cases under these criteria, not proof of absence. Domain suffixes can cover services independently of the apex.",""]
(out/"report.md").write_text("\n".join(lines),encoding="utf-8")
print(json.dumps({"summary":summary,"promoted_count":len(changed)},ensure_ascii=False),flush=True)
