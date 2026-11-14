#!/usr/bin/env python3
"""Review-only GET and DNS diagnostics for a curated GeoSite plan."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor,as_completed
import csv
from datetime import datetime,timezone
from hashlib import sha256
from html.parser import HTMLParser
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import threading
import time
from urllib.parse import urljoin,urlsplit
from prepare import hostname,records

API = "https://api.globalping.io/v1"
ASNS = (3216,12389,207957)
SAFE_ID=re.compile(r"[A-Za-z0-9_-]{1,100}\Z")
ISSUE=re.compile(r"just a moment|checking your browser|access denied|captcha|domain is for sale|buy this domain|домен прода[её]тся|домен припаркован|сайт на обслуживании|database error|доступ.*ограничен",re.I)
BODY_LIMIT=10000

class Page(HTMLParser):
    HIDDEN={"head","script","style","svg","template","noscript"}
    VOID={"area","base","br","col","embed","hr","img","input","link","meta","param","source","track","wbr"}
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden=[]; self.main=[]; self.visible=[]; self.title=[]
        self.in_title=False; self.main_depth=0
    def handle_starttag(self,tag,attrs):
        if tag=="title":
            self.in_title=True
        if self.hidden:
            if tag=="body" and self.hidden==["head"]:
                self.hidden.clear()
            else:
                if tag in self.HIDDEN: self.hidden.append(tag)
                return
        if tag in self.HIDDEN:
            self.hidden.append(tag)
        if tag in {"main","article"}: self.main_depth+=1
    def handle_endtag(self,tag):
        if tag=="title":self.in_title=False
        if self.hidden:
            if tag==self.hidden[-1]:self.hidden.pop()
            return
        if tag in {"main","article"}:self.main_depth=max(0,self.main_depth-1)
    def handle_data(self,data):
        if self.in_title:self.title.append(data)
        if not self.hidden and not self.in_title:
            self.visible.append(data)
            if self.main_depth:self.main.append(data)

def clean(value):
    return " ".join(value.split())

def ip(value):
    try:return ipaddress.ip_address(value)
    except (ValueError,TypeError):return None

def san_match(host,names):
    return any(h==host or (h.startswith("*.") and host.endswith(h[1:]) and host.count(".")==h.count(".")) for h in names)

def probe_summary(row,kind,requested,item):
    p=item.get("probe") or {}
    r=item.get("result") or {}
    a=p.get("asn")
    base=dict(asn=a,country=p.get("country"),network=p.get("network"),probe_tags=p.get("tags") or [],probe_state=r.get("status"))
    if a not in ASNS or p.get("country")!="RU":
        return dict(base,state="unexpected_probe")
    if r.get("status")!="finished":
        return dict(base,state="transport_unproven",failure_source=r.get("failureSource"))
    if kind=="dns":
        answers=[]
        for entry in r.get("answers") or []:
            value=ip(entry.get("value"))
            if value and value.version==requested and entry.get("type")==("A" if requested==4 else "AAAA"):
                answers.append(str(value))
        status=r.get("statusCode")
        return dict(base,state="dns_answer" if answers else "dns_no_answer" if status in (None,0,"NOERROR") else "dns_error_observed",dns_rcode=status,dns_answers=sorted(set(answers)))
    addr=ip(r.get("resolvedAddress"))
    tls=r.get("tls") or {}
    names=[x.lower().rstrip(".") for x in re.findall(r"DNS:([^, ]+)",(tls.get("subject") or {}).get("alt") or "")]
    matched=san_match(row["host"],names)
    hdr={k.lower():v for k,v in (r.get("headers") or {}).items()}
    http=r.get("statusCode")
    location=hdr.get("location")
    dest=urljoin(row["url"],location) if isinstance(location,str) else None
    try:
        parsed=urlsplit(dest or "")
        redirect_host=parsed.hostname
    except ValueError:
        redirect_host=None
    body=(r.get("rawBody") or "")[:BODY_LIMIT]
    page=Page()
    page.feed(body)
    visible=clean(" ".join(page.visible))
    principal=clean(" ".join(page.main))
    title=clean(" ".join(page.title))[:180]
    markers=[m for m in row["markers"].split("|") if m and m.casefold() in (principal or visible).casefold()]
    title_markers=[m for m in row["markers"].split("|") if m and m.casefold() in title.casefold()]
    ctype=str(hdr.get("content-type",""))
    charset_loss="\ufffd" in body
    challenge=ISSUE.search(title+" "+visible)
    if not addr or addr.version!=requested:
        state="address_family_unproven"
    elif tls.get("authorized") is not True or not matched:
        state="tls_unproven"
    elif http in (301,302,303,307,308) and location:
        state="redirect_observed"
    elif not isinstance(http,int) or http!=200:
        state="http_other" if isinstance(http,int) else "transport_unproven"
    elif challenge:
        state="challenge_or_placeholder"
    elif charset_loss:
        state="encoding_loss"
    elif not ctype.lower().startswith(("text/html","application/xhtml+xml")):
        state="non_html_review"
    elif len(visible)<100:
        state="body_unproven"
    elif row["markers"] and not markers:
        state="identity_unproven"
    elif markers and len(principal)>=100:
        state="body_marker_observed"
    else:
        state="visible_body_review"
    return dict(base,state=state,http=http,connected_ip=str(addr) if addr else None,observed_family=addr.version if addr else None,
                tls_trusted=tls.get("authorized"),tls_san_match=matched,tls_error=tls.get("error"),title=title,
                visible_chars=len(visible),main_chars=len(principal),body_chars=len(body),
                body_utf8_sha256=sha256(body.encode()).hexdigest() if body else None,
                api_truncated=r.get("truncated"),encoding_loss=charset_loss,content_type=ctype,
                markers=markers,title_markers=title_markers,challenge=challenge[0] if challenge else None,
                redirect_location=dest,redirect_host=redirect_host,redirect_followed=False)

def request(path,payload=None):
    cmd=["curl","-sS","--max-time","12","--write-out","\n%{http_code}"]
    if payload is not None:
        cmd+=["-H","Content-Type: application/json","--data-binary",json.dumps(payload)]
    s=subprocess.run(cmd+[API+path],capture_output=True,text=True,timeout=16)
    payload,_,status=s.stdout.rpartition("\n")
    try:
        v=json.loads(payload)
        return int(status),v if isinstance(v,dict) else {}
    except (TypeError,ValueError):
        return 0,{}

def quota():
    code,body=request("/limits")
    if code!=200:raise RuntimeError("Globalping quota unavailable")
    v=body["rateLimit"]["measurements"]["create"]
    return v["remaining"],v["reset"]

def build_request(row,kind,family,asns=ASNS):
    u=urlsplit(row["url"])
    path=(u.path or "/")+("?" + u.query if u.query else "")
    q=dict(type="http" if kind=="get" else "dns",target=row["host"],
           locations=[dict(country="RU",asn=n,limit=1) for n in asns])
    q["measurementOptions"]=(dict(protocol="HTTPS",ipVersion=family,request=dict(method="GET",path=path)) if kind=="get"
                             else dict(query=dict(type="A" if family==4 else "AAAA")))
    return q

def same_request(response,body,at,mid):
    if response.get("target")!=body["target"] or response.get("type")!=body["type"] or response.get("id")!=mid:
        return False
    try:
        created=datetime.fromisoformat(response["createdAt"])
        if abs((created-at).total_seconds())>60:return False
    except (KeyError,TypeError,ValueError):return False
    opts=response.get("measurementOptions") or {}
    expect=body["measurementOptions"]
    if body["type"]=="http":
        actual=opts.get("request") or {}
        return actual.get("method")=="GET" and (actual.get("path") or "/")==expect["request"]["path"] and opts.get("protocol","HTTPS")=="HTTPS" and opts.get("ipVersion",4)==expect["ipVersion"]
    # The API elides the default A record type.
    return (opts.get("query") or {}).get("type","A")==expect["query"]["type"]

def task(row,kind,family,stop):
    base=dict(row,test=kind,requested_family=family)
    if stop.is_set():return dict(base,state="not_measured_after_rate_limit")
    body=build_request(row,kind,family)
    at=datetime.now(timezone.utc)
    code,val=request("/measurements",body)
    mid=val.get("id")
    if code==429:stop.set()
    if not (200<=code<300 and isinstance(mid,str) and SAFE_ID.fullmatch(mid)):
        public_error=str(val.get("error") or val.get("type") or "")[:240]
        return dict(base,state="not_measured",api_status=code,api_error=public_error)
    result={}
    for i in range(10):
        if i:time.sleep(1.2)
        code,result=request("/measurements/"+mid)
        if result.get("status")=="finished":break
    base.update(id=mid,submitted_at=at.isoformat(),observed_at=result.get("createdAt"))
    if result.get("status")!="finished":
        return dict(base,state="measurement_unfinished")
    if not same_request(result,body,at,mid):
        return dict(base,state="request_identity_unproven")
    probes=[probe_summary(row,kind,family,x) for x in result.get("results") or []]
    verification=len(probes)==len(ASNS) and {p["asn"] for p in probes}==set(ASNS) and all(p["country"]=="RU" for p in probes)
    states=Counter(p["state"] for p in probes)
    return dict(base,state="observed" if verification else "probe_coverage_incomplete",probes=probes,probe_states=states)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("plan",type=Path)
    p.add_argument("output",type=Path)
    p.add_argument("--test",choices=("get4","get6","a","aaaa"),action="append")
    p.add_argument("--workers",type=int,choices=range(1,7),default=4)
    p.add_argument("--reserve",type=int,default=0)
    args=p.parse_args()
    rows=records(args.plan)
    if not rows or len({r["url"] for r in rows})!=len(rows) or args.reserve<0 or any(hostname(r["url"])!=r["host"] for r in rows):
        p.error("check exact HTTPS URLs and quota reserve")
    opts=dict(get4=("get",4),get6=("get",6),a=("dns",4),aaaa=("dns",6))
    tests=list(dict.fromkeys(args.test or ["get4"]))
    need=len(rows)*len(tests)*len(ASNS)
    available,reset=quota()
    if available<need+args.reserve:
        raise SystemExit(f"Globalping quota {available}; need {need}, reserve {args.reserve}, reset {reset}s")
    stop=threading.Event()
    with args.output.open("x",encoding="utf-8") as out,ThreadPoolExecutor(args.workers) as pool:
        futures={pool.submit(task,r,*opts[t],stop):(r,t) for r in rows for t in tests}
        for f in as_completed(futures):
            r,t=futures[f]
            try:result=f.result()
            except Exception as e:result=dict(r,test=opts[t][0],requested_family=opts[t][1],state="runner_error",error=type(e).__name__)
            out.write(json.dumps(result,ensure_ascii=False,separators=(",",":"))+"\n")
            out.flush()
            print(r["host"],t,result["state"],dict(result.get("probe_states",{})),flush=True)

if __name__=="__main__":main()
