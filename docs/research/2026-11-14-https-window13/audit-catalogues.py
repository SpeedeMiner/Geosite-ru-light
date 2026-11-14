#!/usr/bin/env python3
"""Normalize public exhibitor website fields, retaining source and baseline coverage."""
from collections import Counter
from functools import cache
from hashlib import sha256
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from urllib.parse import urlsplit
import argparse,csv,json,re

from lxml import html

HERE=Path(__file__).resolve().parent
BASE_DAT="9688e3db4d6b11f48b49ec7812978cc233576ebc57166055901c1c6edb970add"

def loadmod(p):
    s=spec_from_file_location(p.stem,p)
    m=module_from_spec(s)
    s.loader.exec_module(m)
    return m

A=loadmod(HERE.parent/"2026-11-14-https-window12"/"audit-catalogues.py")
C=loadmod(HERE/"checkpoint.py")

def digest(p):
    return sha256(p.read_bytes()).hexdigest()

def j(p):
    return json.loads(p.read_text())

def txt(n):
    return " ".join(n.text_content().split())

def doc(p):
    return html.fromstring(p.read_text(encoding="utf-8-sig"))

def write(out,name,rows):
    rows=list(rows)
    with (out/name).open("w",newline="") as f:
        w=csv.DictWriter(f,list(rows[0]),delimiter="\t",lineterminator="\n")
        w.writeheader()
        w.writerows(rows)

def main():
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument("sources",type=Path)
    cli.add_argument("dat",type=Path)
    cli.add_argument("out",type=Path)
    a=cli.parse_args()
    d=a.sources
    raw=a.dat.read_bytes()
    if sha256(raw).hexdigest()!=BASE_DAT: raise ValueError("Expected exact +400 DAT")
    cats=A.G.memberships(raw)
    prev,ids=C.history()
    prevhosts={urlsplit(u).hostname for u in prev}
    @cache
    def coverage(h):
        return ",".join(k for k,rs in cats.items()
                        if any(A.G.REPLAY.match(h,r) for r in rs)) or "uncovered"
    def row(source,name,scope,card,state,site="",fp=None):
        u=urlsplit(site) if "://" in site else urlsplit("https://"+site)
        host=A.normalize(site) if site else ""
        # Normalize only the host; a source URL with credentials is not evidence.
        if u.username or u.password: host=""
        return dict(source=source,name=name,scope=scope,card=card,source_sha256=digest(fp) if fp else "",
                    website=site,host=host,state=state,
                    coverage=coverage(host) if host else "none",
                    previously_measured=str(host in prevhosts).lower() if host else "none")
    records=[]
    food=j(d/"food-index.json")
    regional=j(d/"food-regional-index.json") if (d/"food-regional-index.json").is_file() else {}
    for key,r in {**food["cards"],**regional}.items():
        fp=d/f"prod-card-{key}.html"
        site=""
        scope=r.get("scope","RU")
        state="not_retrieved"
        if fp.is_file():
            fields={txt(n).strip(":"):n.getnext() for n in doc(fp).xpath("//dl/dt")
                    if n.getnext() is not None and n.getnext().tag=="dd"}
            expected={"RU":"Россия","BY":"Республика Беларусь","KZ":"Республика Казахстан"}[scope]
            state="country_not_verified"
            if "Страна" in fields and txt(fields["Страна"])==expected:
                field=fields.get("Сайт")
                site=next(iter(field.xpath(".//a/@href")),txt(field)).strip() if field is not None else ""
                state="website" if A.normalize(site) else "no_website" if not site else "invalid_website"
        records.append(row("prodexpo",r["name"],scope,r["url"],state,site,fp if fp.is_file() else None))
    belagro_web=j(d/"belagro-web.json") if (d/"belagro-web.json").is_file() else {}
    for key,r in j(d/"belagro-index.json").items():
        fp=d/f"belagro-card-{key}.html"
        state="not_retrieved"
        links=[]
        if fp.is_file():
            t=doc(fp)
            links=t.xpath('//main//a[starts-with(@href,"https://") or starts-with(@href,"http://")]/@href')
            state="website" if links else "no_website"
        if not fp.is_file() and belagro_web.get(r["url"],{}).get("contact_excerpt"):
            links=belagro_web[r["url"]]["sites"]
            state="website_web_excerpt" if links else "no_website_web_excerpt"
        for site in dict.fromkeys(links or [""]):
            records.append(row("belagro",r["name"],"RU",r["url"],state,site,fp if fp.is_file() else None))
    astana=j(d/"astanabuild-index.json")
    scopes={"Россия":"RU","Казахстан":"KZ","Беларусь":"BY","Республика Беларусь":"BY"}
    for key,r in astana.items():
        if r["country"] not in scopes: continue
        fp=d/f"astanabuild-card-{key}.html"
        site=""
        state="not_retrieved"
        if fp.is_file():
            t=doc(fp)
            title=t.xpath('//*[@id="lbContractor"]')
            city=t.xpath('//*[@id="lbCity"]')
            w=t.xpath('//*[@id="lbWeb"]')
            state="card_identity_not_verified"
            if len(title)==len(city)==len(w)==1 and txt(title[0])==r["name"] and txt(city[0])==r["city"]:
                site=next(iter(w[0].xpath(".//a/@href")),txt(w[0])).strip()
                state="website" if site else "no_website"
        records.append(row("astanabuild",r["name"],scopes[r["country"]],r["detail"],state,site,fp if fp.is_file() else None))
    trans=j(d/"trans-kz-index.json")
    trans_sample=j(d/"trans-kz-detail-sample.json")
    for key,r in trans_sample.items():
        fp=d/f"trans-kz-card-{key}.html"
        site=""
        state="not_retrieved"
        if fp.is_file():
            t=doc(fp)
            title=t.xpath('//*[@id="lbContractor"]')
            city=t.xpath('//*[@id="lbCity"]')
            w=t.xpath('//*[@id="lbWeb"]')
            state="card_identity_not_verified"
            if len(title)==len(city)==len(w)==1 and txt(title[0])==r["name"] and txt(city[0])==r["city"]:
                site=next(iter(w[0].xpath(".//a/@href")),txt(w[0])).strip()
                state="website" if site else "no_website"
        records.append(row("trans_kz",r["name"],scopes[r["country"]],r["detail"],state,site,fp if fp.is_file() else None))
    for r in j(d/"web-cards.json")+j(d/"operator-cards.json"):
        records.append(row(r.get("source","belprom" if "belpromforum.by" in r["card"] else "transweek"),
                           r["name"],r["scope"],r["card"],r["state"],r["site"]))
    write(a.out,"06-catalogue-coverage.tsv",records)
    summary={}
    for k in sorted({r["source"] for r in records}):
        rows=[r for r in records if r["source"]==k]
        hosts={r["host"]:r["coverage"] for r in rows if r["host"]}
        summary[k]={"rows":len(rows),"cards":len({r["card"] for r in rows}),"states":dict(Counter(r["state"] for r in rows)),
                    "unique_hosts":len(hosts),"coverage":dict(Counter(hosts.values()))}
    summary["input"]={"coverage_sha256":BASE_DAT,"historical_urls":len(prev),
        "food_russia_planned_pages":food["pages"],"food_russia_total_pages":food["page_total"],
        "food_russia_retrieved_pages":len(list(d.glob("prod-russia*.html"))),
        "trans_kz_index_cards":len(trans),"trans_kz_countries":dict(Counter(r["country"] for r in trans.values())),
        "astanabuild_index_cards":len(astana),"astanabuild_countries":dict(Counter(r["country"] for r in astana.values())),
        "sha256":{p.name:digest(p) for p in sorted(d.glob("*.html"))
                  if p.name in {"astanabuild-iteca.html","prod-by.html","prod-kz.html","prod-russia.html","belagro-ru.html","belprom.html","transweek.html","trans-kz-iteca.html"}}}
    (a.out/"06-catalogue-counts.json").write_text(json.dumps(summary,indent=2,ensure_ascii=False)+"\n")

if __name__=="__main__":main()
