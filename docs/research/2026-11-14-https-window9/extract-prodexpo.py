#!/usr/bin/env python3
"""Extract exact organizer cards from a complete ordered set of Prodexpo pages."""
import argparse
import csv
from html import unescape
from pathlib import Path
import re
import sys
from urllib.parse import parse_qs, urlsplit

CARDS = re.compile(
    r'<a\s+data-stand="([^"]+)"\s+href="([^"]+)"[^>]*>\s*<div>'
    r'(?:(?!</a>).)*?<h4 class="list-group-item-heading">(.*?)</h4>', re.S)
EXPO = "/ru/exhibitions/870c9c18-e84b-11ef-80ce-a0d3c1fab97f/exhibitors/"


def extract(pages):
    rows, urls = [], set()
    for number, raw in enumerate(pages, 1):
        if not raw.strip().endswith("</html>"):
            raise ValueError(f"incomplete page {number}")
        found = CARDS.findall(raw)
        if not found:
            raise ValueError(f"no cards on page {number}")
        for stand, link, title in found:
            link = unescape(link)
            u = urlsplit(link)
            if (u.scheme != "https" or u.hostname != "icatalog.expocentr.ru"
                    or not re.fullmatch(re.escape(EXPO) + r"[0-9]+", u.path)
                    or parse_qs(u.query) != {"stand": [stand]} or u.fragment or link in urls):
                raise ValueError(f"invalid or duplicate organizer card on page {number}")
            urls.add(link)
            title = " ".join(unescape(re.sub(r"<[^>]*>", " ", title)).split())
            if not title:
                raise ValueError(f"unnamed card on page {number}")
            rows.append((number, stand, title, link))
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("pages", nargs=9, type=Path, help="pages in numerical order")
    a = p.parse_args()
    rows = extract(x.read_text(encoding="utf-8-sig") for x in a.pages)
    if len(rows) != 86:
        p.error(f"expected 86 cards from the 2026 Belarus filter, found {len(rows)}")
    w = csv.writer(sys.stdout, delimiter="\t", lineterminator="\n")
    w.writerow(("page", "stand", "exhibitor", "organizer_card"))
    w.writerows(rows)


if __name__ == "__main__":
    main()
