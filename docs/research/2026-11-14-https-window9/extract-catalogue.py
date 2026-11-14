#!/usr/bin/env python3
"""Export regional organizer card metadata, not production routing rules."""
import argparse
from collections import Counter
import csv
from html import unescape
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

REGIONAL = {"Казахстан": "KZ", "Республика Беларусь": "BY", "Россия": "RU"}
TABLE = re.compile(r'<td class="exhib-td"[^>]*>(.*?)</td>', re.S)
NAME = re.compile(r"<h2 class='exhib-name'>\s*<a href='([^']+)'[^>]*>(.*?)</a>", re.S)
CITY = re.compile(r"<div class='exhib-city'>(.*?)</div>", re.S)
DESC = re.compile(r"<p class='bg_t_onsite'>(.*?)</p>", re.S)
WEB = re.compile(r"(?<![\w@])(?:https?://|www\.)[a-z0-9][a-z0-9.\-]*(?:/[a-z0-9._~/%\-]*)?", re.I)
ANCHOR = re.compile(r"<a [^>]*href=['\"]([^'\" ]+)", re.I)


def plain(value):
    return " ".join(unescape(re.sub(r"<[^>]*>", " ", value)).split())


def extract(raw, domain):
    all_rows = []
    for row in TABLE.findall(raw):
        a, c = NAME.search(row), CITY.search(row)
        if not a or not c:
            raise ValueError("unexpected exhibitor layout")
        card = unescape(a[1])
        if urlsplit(card).scheme != "https" or urlsplit(card).hostname != domain:
            raise ValueError("unexpected organizer card hostname")
        if [unescape(x) for x in ANCHOR.findall(row)] != [card]:
            raise ValueError("additional anchors require explicit review")
        loc = plain(c[1]).split(" - ", 1)[0]
        desc = DESC.search(row)
        hints = sorted({x.rstrip(".") for x in WEB.findall(plain(desc[1]))}) if desc else []
        all_rows.append((loc, plain(a[2]), card, " ".join(hints)))
    if not all_rows or len({r[2] for r in all_rows}) != len(all_rows):
        raise ValueError("empty or nonunique card list")
    return all_rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("html", type=Path)
    p.add_argument("card_hostname", choices=("translogistica.kz", "kihe.kz"))
    args = p.parse_args()
    rows = extract(args.html.read_text(encoding="utf-8-sig"), args.card_hostname)
    writer = csv.writer(sys.stdout, delimiter="\t", lineterminator="\n")
    writer.writerow(("scope", "exhibitor", "organizer_card", "description_url_hints"))
    writer.writerows((REGIONAL[c], n, u, h or "-") for c, n, u, h in rows if c in REGIONAL)
    counts = Counter(REGIONAL.get(c, "other" if c else "unlabelled") for c, *_ in rows)
    print(f"total={len(rows)} {dict(sorted(counts.items()))}", file=sys.stderr)


if __name__ == "__main__":
    main()
