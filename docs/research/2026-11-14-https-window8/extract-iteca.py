#!/usr/bin/env python3
"""Extract region-tagged organizer cards from the public 2026 Iteca list."""
import argparse
from collections import Counter
import csv
from html import unescape
from pathlib import Path
import re
from urllib.parse import urlsplit


def extract(raw):
    for m in re.finditer(r'<td class="exhib-td exhib-td__small".*?</td>', raw, re.S):
        t = m[0]
        a = re.search(r"<div class='exhib-name'>\s*<a href='([^']+)'[^>]*>(.*?)</a>", t, re.S)
        c = re.search(r"<div class='exhib-country'>(.*?)</div>", t, re.S)
        if not a and not c and "Стенд №" in t:
            continue
        if not a or not c:
            raise ValueError("unexpected exhibitor row")
        country = unescape(c[1]).strip()
        name = unescape(re.sub(r"<[^>]+>", "", a[2])).strip()
        url = unescape(a[1])
        if urlsplit(url).hostname != "translogistica.kz":
            raise ValueError("unexpected card hostname")
        yield country, name, url


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("catalogue", type=Path)
    args = p.parse_args()
    rows = list(extract(args.catalogue.read_text(encoding="utf-8")))
    if len({r[2] for r in rows}) != len(rows):
        p.error("repeated card URLs")
    import sys
    writer = csv.writer(sys.stdout, delimiter="\t", lineterminator="\n")
    writer.writerow(["catalogue_country", "exhibitor", "organizer_card"])
    writer.writerows(r for r in rows if r[0] in {"Россия", "Республика Беларусь", "Казахстан"})
    print(dict(Counter(r[0] for r in rows)), file=sys.stderr)


if __name__ == "__main__":
    main()
