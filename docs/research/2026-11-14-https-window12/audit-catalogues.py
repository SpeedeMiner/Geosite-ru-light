#!/usr/bin/env python3
"""Extract source-provided website fields and compare them to a pinned GeoSite DAT."""
import argparse
from collections import Counter
import csv
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from lxml import html

HERE = Path(__file__).resolve().parent
S = importlib.util.spec_from_file_location("coverage", HERE.parent /
    "2026-11-14-https-window7/verify-coverage.py")
G = importlib.util.module_from_spec(S)
S.loader.exec_module(G)


def document(p):
    return html.fromstring(p.read_text(encoding="utf-8-sig"))


def plain(node):
    return " ".join(node.text_content().split())


def digest(p):
    return sha256(p.read_bytes()).hexdigest()


def normalize(u):
    try:
        p = urlsplit(u if "://" in u else "https://" + u)
        if p.scheme not in {"http", "https"} or p.username is not None or p.password is not None:
            return ""
        h = (p.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
    except (ValueError, UnicodeError):
        return ""
    return h if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z0-9-]+", h) else ""


def write(out, filename, keys, rows):
    with (out / filename).open("w", newline="") as f:
        w = csv.DictWriter(f, keys, delimiter="\t", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("sources", type=Path)
    p.add_argument("dat", type=Path)
    p.add_argument("out", type=Path)
    args = p.parse_args()
    src, out = args.sources, args.out
    dat = args.dat.read_bytes()
    cats = G.memberships(dat)

    def coverage(h):
        if not h:
            return "no_website"
        return ",".join(k for k, rules in cats.items()
                        if any(G.REPLAY.match(h, r) for r in rules)) or "uncovered"

    moap = src / "moa.html"
    moa = []
    for a in document(moap).xpath('//div[@class="inner-html"]//a[starts-with(@href,"https://")]'):
        u = a.get("href")
        h = normalize(u)
        if h and h.endswith(".kz") and h != "www.gov.kz":
            moa.append(dict(website=u, host=h, coverage=coverage(h)))
    if len(moa) != 14:
        p.error("unexpected agriculture ministry website count")
    write(out, "02-moa-coverage.tsv", list(moa[0]), moa)

    agr = []
    for li in document(src / "agritek.html").xpath('//*[@id="col"]//ul/li'):
        t = plain(li)
        if t.startswith("№ стенда"):
            continue
        if t == "Строительства»)" and agr[-1]["exhibitor"].endswith("Стальные Технологии"):
            agr[-1]["exhibitor"] += " " + t
            continue
        m = re.fullmatch(r"(\d+(?:-\d+)?|[-–—]|Наруж) (.+)", t)
        if m:
            agr.append(dict(stand=m[1], exhibitor=m[2]))
        elif t == "Аналитический научно-производственный журнал «АГРОТАЙМ»":
            agr.append(dict(stand="", exhibitor=t))
        else:
            p.error("unexpected agriculture catalogue row: " + t)
    write(out, "02-agritek-exhibitors.tsv", list(agr[0]), agr)

    midx = json.loads((src / "mining-card-index.json").read_text())
    mining = []
    for r in midx:
        file = src / ("mine-card-" + r["key"] + ".html")
        v = dict(country=r["country"], exhibitor=r["name"], organizer_card=r["card"],
                 detail=r["detail"], detail_sha256="", website="", host="", state="not_retrieved",
                 coverage="unresolved")
        if file.is_file() and file.stat().st_size:
            t = document(file)
            title = t.xpath('//*[@id="lbContractor"]')
            web = t.xpath('//*[@id="lbWeb"]')
            if len(title) == len(web) == 1 and plain(title[0]) == r["name"]:
                v.update(detail_sha256=digest(file))
                u = next(iter(web[0].xpath(".//a/@href")), plain(web[0])).strip()
                h = normalize(u) if u else ""
                v.update(website=u if h else "",host=h,coverage=coverage(h),
                         state="website" if h else "unparsed_website" if u else "no_website")
            else:
                v.update(state="identity_unverified")
        mining.append(v)
    write(out, "02-mining-regional-cards.tsv", list(mining[0]), mining)

    idx = json.loads((src / "furniture-card-index.json").read_text())
    fr = []
    for key, r in idx.items():
        file = src / ("furn-card-" + key + ".html")
        v = dict(card_id=key, index_page=r["page"], exhibitor=r["name"],
                 organizer_card=r["url"], card_sha256="", website="", host="",
                 state="not_retrieved", coverage="unresolved")
        if file.is_file() and file.stat().st_size:
            t = document(file)
            fields = {plain(n).strip(":"):n.getnext() for n in t.xpath("//dl/dt")
                      if n.getnext() is not None and n.getnext().tag == "dd"}
            if "Страна" in fields and plain(fields["Страна"]) == "Россия":
                v.update(card_sha256=digest(file))
                field = fields.get("Сайт")
                u = next(iter(field.xpath(".//a/@href")),plain(field)).strip() if field is not None else ""
                h = normalize(u) if u else ""
                v.update(website=u if h else "",host=h,coverage=coverage(h),
                         state="website" if h else "unparsed_website" if u else "no_website")
            else:
                v.update(state="identity_unverified")
        fr.append(v)
    write(out, "02-furniture-russia-cards.tsv", list(fr[0]), fr)
    allcountries = Counter(plain(x) for x in document(src / "mmca-list.html").xpath('//*[@class="exhib-country"]'))
    inputs = ("moa.html", "agritek.html", "mmca-list.html", "furn-russia.html")
    info = dict(dat_sha256=sha256(dat).hexdigest(),
                source_sha256={n:digest(src/n) for n in inputs},
                ministry=dict(total=len(moa),coverage=Counter(r["coverage"] for r in moa)),
                agritek=dict(exhibitor_rows=len(agr), explicit_website_fields=0),
                mining=dict(rows=sum(allcountries.values()), countries=allcountries,
                            regional_cards=len(mining), cards=Counter(r["state"] for r in mining),
                            coverage=Counter(r["coverage"] for r in mining)),
                furniture=dict(index_cards=len(fr),cards=Counter(r["state"] for r in fr),
                               unique_hosts=len({r["host"] for r in fr if r["host"]}),
                               uncovered_hosts=sorted({r["host"] for r in fr if r["coverage"] == "uncovered"})))
    (out/"02-catalogue-counts.json").write_text(json.dumps(info,ensure_ascii=False,indent=2)+"\n")


if __name__ == "__main__":
    main()
