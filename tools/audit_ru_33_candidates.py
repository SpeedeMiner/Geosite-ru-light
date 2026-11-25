#!/usr/bin/env python3
"""Investigate previously identified 33 names without changing routing."""
import asyncio,csv,datetime,json,re,socket
from pathlib import Path
import aiohttp,dns.asyncresolver,dns.query,dns.message,dns.rcode,dns.flags,dns.resolver,dns.rdatatype
from publicsuffix2 import get_tld

root=Path("existing")
with (root/"removal-review.csv").open(encoding="utf-8",newline="") as f: candidates=list(csv.DictReader(f))
if len(candidates)!=33: raise SystemExit("expected exactly 33 candidates")
registrations=json.loads((root/"rdap-authoritative.json").read_text(encoding="utf-8"))["results"]
allreg=json.loads((root/"registration.json").read_text(encoding="utf-8"))
bootstrap=json.loads(Path("dns-bootstrap.json").read_text(encoding="utf-8"))
services={suffix.lower():next((u.rstrip("/") for u in urls if u.startswith("https://")),None) for names,urls in bootstrap["services"] for suffix in names}
sem=asyncio.Semaphore(6)
async def authoritatives(zone,domain):
    try:
        ans=await dns.asyncresolver.resolve(zone,"NS",lifetime=5)
        ns=[str(x.target).rstrip(".") for x in ans][:2]
    except Exception as e: return {"stage":"zone_ns", "error":type(e).__name__}
    output=[]
    for name in ns:
        try:
            ips=await dns.asyncresolver.resolve(name,"A",lifetime=4)
            addr=str(ips[0])
            def query():
                q=dns.message.make_query(domain,"NS",want_dnssec=True)
                return dns.query.udp(q,addr,timeout=3)
            response=await asyncio.to_thread(query)
            output.append({"server":name,"ip":addr,"rcode":dns.rcode.to_text(response.rcode()),
                "aa":bool(response.flags & dns.flags.AA),"answer":[x.to_text() for x in response.answer],
                "authority":[x.to_text() for x in response.authority]})
        except Exception as e:output.append({"server":name,"error":type(e).__name__})
    return output

def whois_query(server,query):
    try:
        with socket.create_connection((server,43),timeout=4) as s:
            s.settimeout(4);s.sendall((query+"\r\n").encode())
            data=b""
            while len(data)<65536:
                b=s.recv(8192)
                if not b: break
                data+=b
            # Keep only evidence of status/registration, not registrant contacts.
            lines=data.decode("utf-8",errors="replace").splitlines()
            terms=("no match","not found","no data found","no entries found","status:","expiration date","expiry date","free","available","whois:")
            selected=[line.strip()[:400] for line in lines if any(t in line.lower() for t in terms)]
            return {"server":server,"lines":selected[:30],"bytes":len(data)}
    except Exception as e:return {"server":server,"error":type(e).__name__}
async def whois(domain,zone):
    iana=await asyncio.to_thread(whois_query,"whois.iana.org",zone)
    refer=next((s.split(":",1)[1].strip() for s in iana.get("lines",[]) if s.lower().startswith("whois:")),None)
    if not refer:return {"iana":iana,"registry":{"error":"no IANA WHOIS referral"}}
    return {"iana":iana,"registry":await asyncio.to_thread(whois_query,refer,domain)}
def occurrences(domain):
    found=[]
    for directory in ("local","data"):
        for p in Path(directory).rglob("*"):
            if not p.is_file() or p.stat().st_size>5_000_000:continue
            try:
                for n,line in enumerate(p.read_text(encoding="utf-8").splitlines(),1):
                    if re.search(r"(?<![a-z0-9-])"+re.escape(domain)+r"(?![a-z0-9-])",line,re.I):
                        found.append({"path":str(p),"line":n,"text":line[:400]})
            except (UnicodeError,OSError):pass
    return found[:40]
async def main():
 async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12),trust_env=False,headers={"User-Agent":"Geosite-RU-Audit/1.0"}) as session:
  async def one(row):
   async with sem:
    domain=row["registrable_domain"];zone=get_tld(domain,strict=True)
    record={"host":row["hostname"],"domain":domain,"zone":zone,"rule_type":row["rule_types"],
            "previous_rdap":registrations.get(domain,{}),"source_occurrences":occurrences(domain),
            "limitations":["source occurrences in local/data do not establish all upstream provenance","parent-zone DNS denial does not alone determine past registration history"]}
    if not zone: record["error"]="cannot identify public suffix";return record
    rdapurl=services.get(zone)
    async def rdap():
     if not rdapurl:return {"error":"no HTTPS RDAP service"}
     try:
      async with session.get(rdapurl+"/domain/"+domain,allow_redirects=True) as r:
       text=await r.text()
       return {"url":str(r.url),"http":r.status,"retry_after":r.headers.get("Retry-After"),"body":text[:2500]}
     except Exception as e:return {"error":type(e).__name__}
    auth,w,registry=await asyncio.gather(authoritatives(zone,domain),whois(domain,zone),rdap())
    record.update(authoritative_dns=auth,whois=w,rdap=registry)
    return record
  return await asyncio.gather(*(one(row) for row in candidates))
records=asyncio.run(main())
out=Path("candidate-audit");out.mkdir(exist_ok=True)
(out/"candidate-evidence.json").write_text(json.dumps({"time":datetime.datetime.now(datetime.timezone.utc).isoformat(),"records":records},ensure_ascii=False,indent=2),encoding="utf-8")
summary=[]
for r in records:
    answers=r.get("authoritative_dns",[])
    authoritative=[a for a in answers if isinstance(a,dict) and a.get("aa")] if isinstance(answers,list) else []
    neg=[a for a in authoritative if a.get("rcode")=="NXDOMAIN" or (a.get("rcode")=="NOERROR" and not a.get("answer"))]
    positive=[a for a in authoritative if a.get("answer")]
    status="authority_negative" if neg and not positive else "authority_positive" if positive else "authority_inconclusive"
    summary.append({"host":r["host"],"zone":r.get("zone"),"dns":status,"rdap":r.get("rdap",{}).get("http"),"whois":r.get("whois",{}).get("registry",{}),"source_occurrences":r["source_occurrences"]})
(out/"summary.json").write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding="utf-8")
print(json.dumps({"count":len(summary),"rows":summary},ensure_ascii=False),flush=True)
