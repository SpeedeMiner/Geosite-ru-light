#!/usr/bin/env python3
"""Classify all retained RU observations and diagnose unresolved hosts."""
import asyncio, collections, csv, datetime, ipaddress, json, re, socket, ssl
from pathlib import Path
import aiohttp
import dns.asyncresolver
import dns.resolver
import dns.exception
from publicsuffix2 import get_sld
import audit_ru_liveness as audit

EXPECTED=4495
OUT=Path("freshness-results"); OUT.mkdir(exist_ok=True)
data=json.loads(Path("preserved/report.json").read_text(encoding="utf-8"))
hosts=data["hosts"]
if len(hosts)!=EXPECTED: raise SystemExit("unexpected host count")
# Existing samples originate from the VPN runs; new samples are separately labelled.
def observation_list(item):
    return item.get("baseline",[])+item.get("targeted",[])
def evidence(o):
    return o.get("evidence") or {}
def valid_available(o):
    return o.get("state")=="available" and evidence(o).get("result")=="available" and o.get("vpn_country")=="RU" and o.get("asn_conflict") is False and o.get("verified_by_sources",0)>=2
def reason(o):
    e=evidence(o)
    return str(e.get("reason") or e.get("result") or o.get("state") or "unrecorded")
pending=[h for h,item in hosts.items() if not any(valid_available(o) for o in observation_list(item))]
sem=asyncio.Semaphore(40)
rdap_sem=asyncio.Semaphore(3)
rdap_cache={}
results={}
async def http_probe(host):
    # DNS is resolved first; explicitly bind to a public IP, never follow redirects.
    d=await audit.resolve(host,True)
    ips=[p for t in ("A","AAAA") for p in d[t]["ips"] if audit.public(p)]
    if not ips: return {"dns":d,"result":"no_public_address"}
    con=aiohttp.TCPConnector(resolver=audit.FixedResolver(ips[0]),use_dns_cache=False)
    try:
        async with aiohttp.ClientSession(connector=con,timeout=aiohttp.ClientTimeout(total=10),trust_env=False,headers=audit.HEADERS) as s:
            async with s.get("http://"+host+"/",allow_redirects=False) as r:
                b=await r.content.read(16384)
                body=audit.normalize(b.decode("utf-8",errors="replace"))
                signal=next((p for p in audit.PARK if re.search(p,body)),None)
                return {"dns":d,"ip":ips[0],"status":r.status,"location":audit.safe_url(__import__("urllib.parse",fromlist=["urljoin"]).urljoin("http://"+host+"/",r.headers.get("Location",""))) if r.headers.get("Location") else None,"parking_signal":signal}
    except Exception as e: return {"dns":d,"ip":ips[0],"error":type(e).__name__}
async def independent_dns(host):
    resolver=dns.asyncresolver.Resolver(configure=False); resolver.nameservers=["1.1.1.1","8.8.8.8"];resolver.lifetime=4
    async def query(kind):
        try:
            a=await resolver.resolve(host,kind,raise_on_no_answer=False)
            return {"status":"ok" if a.rrset else "NODATA","ips":[str(x) for x in a] if a.rrset else []}
        except dns.resolver.NXDOMAIN: return {"status":"NXDOMAIN","ips":[]}
        except dns.exception.Timeout: return {"status":"timeout","ips":[]}
        except Exception as e: return {"status":type(e).__name__,"ips":[]}
    a,aaaa=await asyncio.gather(query("A"),query("AAAA"))
    return {"A":a,"AAAA":aaaa}
async def registration(session,host):
    domain=get_sld(host,strict=True)
    if not domain: return {"status":"unavailable","reason":"registrable domain not resolved"}
    if domain in rdap_cache: return rdap_cache[domain]
    async with rdap_sem:
        try:
            async with session.get("https://rdap.org/domain/"+domain,allow_redirects=True,timeout=aiohttp.ClientTimeout(total=12)) as r:
                if r.status!=200: result={"domain":domain,"http":r.status,"status":"inconclusive"}
                else:
                    d=await r.json(content_type=None)
                    events=[{"eventAction":e.get("eventAction"),"eventDate":e.get("eventDate")} for e in d.get("events",[]) if "expir" in str(e.get("eventAction","")).lower()]
                    result={"domain":domain,"http":r.status,"status":"record_found","registry_status":d.get("status",[]),"expiry_events":events}
        except Exception as e: result={"domain":domain,"status":"inconclusive","reason":type(e).__name__}
    rdap_cache[domain]=result
    return result
async def main():
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12),trust_env=False,headers=audit.HEADERS) as session:
        point={}
        for url in ("https://ipapi.co/json/","https://ipinfo.io/json"):
            try:
                async with session.get(url) as r:
                    j=await r.json(content_type=None)
                    point[url]={"ip":j.get("ip"),"country":j.get("country_code") or j.get("country"),"status":r.status}
            except Exception as e: point[url]={"error":type(e).__name__}
        queue=asyncio.Queue()
        for h in pending: queue.put_nowait(h)
        async def worker():
            while True:
                try: h=queue.get_nowait()
                except asyncio.QueueEmpty: return
                try:
                    async with sem:
                        https,dns_other=await asyncio.gather(audit.probe(h,True),independent_dns(h))
                        http=await http_probe(h)
                        dns= https.get("dns",{})
                        nxdomain=all(dns.get(t,{}).get("status")=="NXDOMAIN" for t in ("A","AAAA"))
                        park= https.get("result")=="parking" or bool(http.get("parking_signal"))
                        rdap=await registration(session,h) if nxdomain or park else {"status":"not_requested","reason":"DNS resolves or registration query not decisive"}
                        results[h]={"point":"GitHub-hosted runner; country separately checked, not assumed","https":https,"http":http,"independent_dns":dns_other,"rdap":rdap}
                except Exception as e:
                    results[h]={"error":type(e).__name__,"reason":str(e)[:200]}
                finally: queue.task_done()
        await asyncio.gather(*(worker() for _ in range(40)))
    categories={k:[] for k in ("ALIVE","INFRASTRUCTURE","GEO_BLOCKED","PARKED","EXPIRED","DEAD","UNKNOWN")}
    table=[]
    for h,item in sorted(hosts.items()):
        old=observation_list(item); extra=results.get(h)
        alive=[o for o in old if valid_available(o)]
        if alive:
            cat="ALIVE"; why="RU VPN: valid TLS and nonempty HTTP 2xx; observed in "+", ".join(sorted({str(o.get("vpn_asn")) for o in alive}))
        else:
            cat="UNKNOWN"
            why="No confirmed RU content response; RU: "+"; ".join(sorted(set(reason(o) for o in old)))[:900]
            if extra:
                hres=extra.get("https",{})
                why+="; external HTTPS: "+str(hres.get("result") or extra.get("error","unknown"))+" / "+str(hres.get("reason","unknown"))
                why+="; HTTP: "+str((extra.get("http") or {}).get("status") or (extra.get("http") or {}).get("error") or (extra.get("http") or {}).get("result","unknown"))
                why+="; registration: "+str((extra.get("rdap") or {}).get("status","unknown"))
        categories[cat].append(h)
        table.append({"hostname":h,"category":cat,"reason":why,"rule_types":";".join(sorted({r["type"] for r in item["rules"]})),
          "ru_observations":len(old),"ru_states":";".join(str(o.get("state","unknown")) for o in old),"external_checked":bool(extra)})
    if sum(map(len,categories.values()))!=EXPECTED or len(results)!=len(pending): raise SystemExit("coverage mismatch")
    summary={k:{"count":len(v),"percent":round(len(v)*100/EXPECTED,2)} for k,v in categories.items()}
    meta={"total":EXPECTED,"pending_external":len(pending),"source_run":45445214672,"time":datetime.datetime.now(datetime.timezone.utc).isoformat(),
          "vantage":point,"limitations":["RU exit attribution in historic observations is self-reported; original provider replies and packets not retained",
          "External IP country must not be assumed from hosted runner",
          "401/403/404 and HTTPS-only failure are not evidence of a dead service",
          "Registration expiry timestamp or RDAP 404 alone does not prove deletion",
          "No parking or geoblock category without corroborating evidence",
          "A domain suffix root does not represent every subdomain"]}
    (OUT/"summary.json").write_text(json.dumps({"meta":meta,"categories":summary},ensure_ascii=False,indent=2),encoding="utf-8")
    (OUT/"classification.json").write_text(json.dumps({"metadata":meta,"summary":summary,"rows":table,"external_evidence":results},ensure_ascii=False),encoding="utf-8")
    with (OUT/"classification.csv").open("w",encoding="utf-8",newline="") as f:
        w=csv.DictWriter(f,fieldnames=list(table[0]));w.writeheader();w.writerows(table)
    for k,v in categories.items(): (OUT/(k+".txt")).write_text("\n".join(v)+("\n" if v else ""),encoding="utf-8")
    (OUT/"removal-candidates.md").write_text("# Removal candidates\n\nNone confirmed. UNKNOWN is not a removal decision; domain suffixes and service infrastructure need functional review.\n",encoding="utf-8")
    lines=["# RU FQDN freshness","",f"Total: {EXPECTED}; targeted external checks: {len(pending)}.","","| Category | Count | Percent |","|---|---:|---:|"]
    for k,v in summary.items(): lines.append(f"| {k} | {v['count']} | {v['percent']:.2f}% |")
    lines+=["","See classification.csv for each FQDN and its reason. See classification.json for retained targeted observations, DNS, HTTPS, HTTP and registration evidence. No removal follows automatically.","","## Limits",""]+["- "+x for x in meta["limitations"]]
    (OUT/"report.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
    print(json.dumps({"metadata":meta,"categories":summary},ensure_ascii=False),flush=True)
if __name__=="__main__": asyncio.run(main())
