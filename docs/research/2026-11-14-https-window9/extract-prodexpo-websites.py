#!/usr/bin/env python3
"""Report organizer-labelled websites without promoting them to routing rules."""
import argparse
import csv
from hashlib import sha256
from html import unescape
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

FIELD = re.compile(r"<dt>\s*(?:Сайт|Веб-сайт)[^<]*</dt>\s*<dd>(.*?)</dd>", re.I | re.S)
ANCHOR = re.compile(r'<a\s+href="([^"]+)"', re.I)


def websites(raw):
    values = set()
    for field in FIELD.findall(raw):
        for href in ANCHOR.findall(field):
            u = unescape(href).strip()
            p = urlsplit(u)
            if p.scheme in {"https", "http"} and p.hostname and not p.username and not p.password:
                values.add(u)
    return sorted(values)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("capture", type=Path)
    args = p.parse_args()
    writer = csv.writer(sys.stdout, delimiter="\t", lineterminator="\n")
    writer.writerow(("exhibitor", "organizer_card", "fetch_status", "website_as_listed", "snapshot_sha256"))
    seen = set()
    for receipt in sorted(args.capture.glob("fetch*.tsv")):
        for row in csv.reader(receipt.open(), delimiter="\t"):
            if len(row) != 5:
                raise ValueError("incomplete receipt")
            ident, name, card, rc, result = row
            if not ident.isdecimal() or ident in seen:
                raise ValueError(f"invalid or repeated card ID: {ident}")
            seen.add(ident)
            if rc != "0" or not result.startswith("200 "):
                writer.writerow((name, card, "fetch_unproven", "", ""))
                continue
            snapshot = (args.capture / (ident + ".html")).read_bytes()
            if not snapshot.rstrip().endswith(b"</html>"):
                writer.writerow((name, card, "incomplete_html", "", ""))
                continue
            found = websites(snapshot.decode("utf-8-sig"))
            writer.writerow((name, card, "listed" if found else "no_website_field",
                             " ".join(found), sha256(snapshot).hexdigest()))


if __name__ == "__main__":
    main()
