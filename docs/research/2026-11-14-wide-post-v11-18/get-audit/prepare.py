#!/usr/bin/env python3
"""Build separate immutable inventory and pilot plans from pinned GeoSite inputs."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

LIGHT_V1118 = "6f5fbc20e045a7314603d115931bff1bdd82a22788fd38ecc8f5578171b1329c"
SERVER_V1118 = "e9d343e6a83c848b0c280af351da956a9bb8275752424d6437244fd47eae7282"
FIELDS = ["cohort", "type", "rule", "host", "url", "markers", "source"]
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")

def varint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise ValueError("invalid protobuf varint")

def fields(data):
    i = 0
    while i < len(data):
        key, i = varint(data, i)
        if key & 7 == 0:
            value, i = varint(data, i)
        elif key & 7 == 2:
            n, i = varint(data, i)
            if i + n > len(data):
                raise ValueError("truncated protobuf field")
            value = data[i:i+n]
            i += n
        else:
            raise ValueError("unexpected wire type")
        yield key >> 3, value

def ru(path, expected):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(f"unexpected SHA-256: {path.name}")
    categories = [list(fields(value)) for key, value in fields(data) if key == 1]
    items, = [item for item in categories if dict(item)[1] == b"RU"]
    result = []
    for key, val in items:
        if key == 2:
            entry = dict(fields(val))
            result.append((entry.get(1,0), entry[2].decode("ascii")))
    if len(result) != len(set(result)) or any(kind not in (2,3) for kind, _ in result):
        raise ValueError("unexpected RU rules")
    return set(result)

def records(path):
    with path.open(encoding="utf-8",newline="") as f:
        return list(csv.DictReader(f,delimiter="\t"))

def write(path, cols, rows):
    with path.open("x",encoding="utf-8",newline="") as f:
        w=csv.DictWriter(f,cols,delimiter="\t",lineterminator="\n")
        w.writeheader()
        w.writerows(rows)

def hostname(url):
    p=urlsplit(url)
    if p.scheme!="https" or not p.hostname or p.netloc!=p.hostname or p.fragment or len(p.hostname)>253 or "." not in p.hostname or not all(LABEL.fullmatch(s) for s in p.hostname.split(".")):
        raise ValueError(f"not a public canonical HTTPS URL: {url}")
    return p.hostname

def row(cohort, kind, rule, url, markers="", source=""):
    return dict(cohort=cohort,type=kind,rule=rule,host=hostname(url),url=url,markers=markers,source=source)

def build(light,server,candidate,queue,proven,curated,out):
    L,S=ru(light,LIGHT_V1118),ru(server,SERVER_V1118)
    exact=sorted(v for k,v in L if k==3)
    if set(exact)!={v for k,v in S if k==3}:
        raise ValueError("Light and Server exact inventories differ")
    additions=candidate.read_text(encoding="utf-8").splitlines()
    names=[x.removeprefix("full:") for x in additions if x.startswith("full:")]
    if len(names)!=len(additions) or len(names)!=len(set(names)) or any(h==v or (k==2 and h.endswith("."+v)) for h in names for k,v in L|S):
        raise ValueError("candidate invalid or already matched")
    proof={}
    for f in proven:
        for s in records(f):
            # Only the earlier explicitly approved URL serves as historical evidence.
            if "proved_url" in s:
                dest=s["proved_url"]
            elif s.get("decision")=="approved_candidate":
                dest=(s.get("exact_urls") or "").split("|")[0]
            else:
                continue
            if dest and hostname(dest)==s["host"]:
                proof[s["host"]]=dest
    for s in records(curated):
        if hostname(s["url"])!=s["host"]:
            raise ValueError("curated URL does not match host")
        if s["cohort"] in ("candidate","baseline"):
            proof[s["host"]]=s["url"]
    release=[row("baseline","full",h,proof.get(h,"https://"+h+"/")) for h in exact]
    pilots=[]
    entry={s["host"]:s for s in records(curated)}
    for s in records(queue):
        x=entry.get(s["host"],{})
        pilots.append(row("hold","candidate",s["host"],x.get("url") or s["url"],x.get("markers",""),s["primary"]))
    for h in names:
        x=entry.get(h,{})
        pilots.append(row("candidate","full",h,proof.get(h,"https://"+h+"/"),x.get("markers",""),proof.get(h,"")))
    for s in records(curated):
        if s["cohort"] in ("baseline","suffix_sample","control"):
            k=s["type"]
            h=s["host"]
            v=s["rule"]
            if (k=="full" and ((3,v) not in L or h!=v)) or (k=="domain" and ((2,v) not in L or not (h==v or h.endswith("."+v)))):
                raise ValueError(f"curated release inventory mismatch: {h}")
            pilots.append(row(s["cohort"],k,v,s["url"],s["markers"],s["source"]))
    if len({s["url"] for s in pilots})!=len(pilots):
        raise ValueError("duplicate pilot URL")
    out.mkdir(parents=True)
    write(out/"pilot.tsv",FIELDS,pilots)
    write(out/"baseline-exact.tsv",FIELDS,release)
    write(out/"suffix-inventory.tsv",["type","rule","light","server"],[dict(type="domain",rule=v,light=int((2,v) in L),server=int((2,v) in S)) for v in sorted({v for k,v in L|S if k==2})])
    summary=dict(light_exact=len(exact),server_exact=len(exact),light_suffix=sum(k==2 for k,v in L),server_suffix=sum(k==2 for k,v in S),pilots=len(pilots),candidate=len(names))
    (out/"inventory.json").write_text(json.dumps(summary,indent=2)+"\n")
    print(summary)

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for a in ("light","server","candidate","queue","curated","out"):p.add_argument(a,type=Path)
    p.add_argument("--proven",type=Path,action="append",default=[])
    a=p.parse_args()
    build(a.light,a.server,a.candidate,a.queue,a.proven,a.curated,a.out)
