#!/usr/bin/env python3
"""Reproduce the public catalogue counts and exact site-field inventory."""
import argparse
from collections import Counter
import csv
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
from urllib.parse import urlsplit

from lxml import html

HERE = Path(__file__).resolve().parent
PREV = HERE.parent / "2026-11-14-https-window7"
SPEC = importlib.util.spec_from_file_location("coverage", PREV / "verify-coverage.py")
G = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(G)
REGIONS = {"Россия", "Казахстан", "Республика Беларусь"}
KIOGE_REGIONS = {"Russia", "Kazakhstan", "Belarus"}


def load(path):
    return html.fromstring(path.read_text(encoding="utf-8-sig"))


def plain(node):
    return " ".join(node.text_content().split())


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def host(value):
    if not value or "@" in value or len(value.split()) != 1:
        return ""
    parts = urlsplit(value if "://" in value else "https://" + value)
    if not parts.hostname or "." not in parts.hostname:
        return ""
    return parts.hostname.encode("idna").decode("ascii").lower()


def save(out, name, keys, rows):
    with (out / name).open("w", newline="") as f:
        w = csv.DictWriter(f, keys, delimiter="\t", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("sources", type=Path)
    p.add_argument("before", type=Path)
    p.add_argument("after", type=Path)
    p.add_argument("output", type=Path)
    args = p.parse_args()
    d, out = args.sources, args.output
    before, after = (G.memberships(x.read_bytes()) for x in (args.before, args.after))

    def covered(h, cats):
        if not h:
            return "no_website"
        return ",".join(k for k, v in cats.items() if any(G.REPLAY.match(h, r) for r in v)) or "uncovered"

    power = load(d / "power.html")
    pc = Counter()
    prow = []
    for row in power.xpath('//td[@class="exhib-td"]'):
        a, = row.xpath('.//h2[@class="exhib-name"]/a')
        city, = row.xpath('.//*[@class="exhib-city"]')
        country = plain(city).split(" - ")[0]
        pc[country] += 1
        card = a.get("href")
        fields = dict(country=country, exhibitor=plain(a), organizer_card=card)
        if country in {"Казахстан", "Республика Беларусь"}:
            q = urlsplit(card).query
            doc = d / ("power-card-" + q.rsplit("=", 1)[-1] + ".html")
            node = load(doc)
            web, = node.xpath('//*[@id="lbWeb"]')
            owner, = node.xpath('//*[@id="lbContractor"]')
            if plain(owner) != fields["exhibitor"]:
                p.error(f"card identity mismatch: {doc.name}")
            fields.update(detail="https://reg.iteca.kz/list/exponent/detailsfull.aspx?" + q,
                          detail_sha256=digest(doc), website=host(plain(web)),
                          website_field="explicit" if plain(web) or web.xpath(".//a") else "empty")
            prow.append(fields)
    save(out, "14-powerexpo-cards.tsv", list(prow[0]), prow)

    k = load(d / "kioge-list.html")
    kc = Counter()
    kr = []
    for row in k.xpath('//td[contains(@class,"exhib-td")]'):
        a = row.xpath('.//*[@class="exhib-name"]/a')
        c = row.xpath('.//*[@class="exhib-country"]')
        if not a and not c:
            continue
        if len(a) != 1 or len(c) != 1:
            p.error("unexpected KIOGE row")
        country = plain(c[0])
        kc[country] += 1
        if country in KIOGE_REGIONS:
            kr.append(dict(country=country, exhibitor=plain(a[0]), organizer_card=a[0].get("href")))
    save(out, "14-kioge-regional.tsv", list(kr[0]), kr)

    e = load(d / "electronics.html")
    ids = {i.get("data-exib") for i in e.xpath('//div[@data-exib and contains(@class,"participant")]')}
    er = []
    for id in sorted(x for x in ids if x and x.isdecimal()):
        src = d / f"ee-{id}.json"
        card, = json.loads(src.read_text(encoding="utf-8-sig"))
        h = host(card["Site"])
        er.append(dict(card_id=id, name=card["Name"], country=card["Country"], site_host=h,
                       before=covered(h, before), after=covered(h, after),
                       card_sha256=digest(src)))
    save(out, "14-electronics-first-page.tsv", list(er[0]), er)

    with (PREV / "12-electronics-coverage.tsv").open() as f:
        rr = [{k: r[k] for k in ("page", "line", "country", "host")}
              for r in csv.DictReader(f, delimiter="\t")]
    for r in rr:
        r.update(before=covered(r["host"], before), after=covered(r["host"], after))
    save(out, "14-electronics-coverage.tsv", list(rr[0]), rr)

    source = {k: digest(d / k) for k in ("power.html", "kioge-list.html", "electronics.html", "electronics.pdf")}
    counts = dict(source_sha256=source,
                  power=dict(rows=pc.total(), by_country=pc, detail_rows=len(prow),
                             explicit_sites=sum(r["website_field"] == "explicit" for r in prow)),
                  kioge=dict(rows=kc.total(), by_country=kc, regional_rows=len(kr)),
                  electronics_first_page=dict(rows=len(er), website_rows=sum(bool(r["site_host"]) for r in er),
                                              after=Counter(r["after"] for r in er)),
                  electronics_pdf=dict(website_rows=len(rr), before=Counter(r["before"] for r in rr),
                                       after=Counter(r["after"] for r in rr)))
    (out / "14-catalogue-counts.json").write_text(json.dumps(counts, ensure_ascii=False, indent=2) + "\n")


if __name__ == "__main__":
    main()
