#!/usr/bin/env python3
"""Summarize the pinned ministry workbook without exporting contact values."""
import argparse
from collections import Counter
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import re
from xml.etree import ElementTree as ET
from zipfile import ZipFile

NS = {"s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
HEADER = ("адрес", "название", "название", "Регион", "id", "отрасль")
EXPLICIT = re.compile(r"(?<![@\w])(?:https?://|www\.)", re.I)


def audit(payload):
    with ZipFile(BytesIO(payload)) as z:
        sheet = ET.fromstring(z.read("xl/worksheets/sheet1.xml"))
        strings = ["".join(x.text or "" for x in i.findall(".//s:t", NS))
                   for i in ET.fromstring(z.read("xl/sharedStrings.xml")).findall("s:si", NS)]
    cells = []
    for row in sheet.findall("s:sheetData/s:row", NS):
        columns = {}
        for c in row.findall("s:c", NS):
            ref = c.attrib["r"]
            if not re.fullmatch(r"[A-F][1-9][0-9]*", ref) or c.get("t") != "s":
                raise ValueError(f"unexpected cell: {ref}")
            columns[ref[0]] = strings[int(c.findtext("s:v", namespaces=NS))].strip()
        cells.append(tuple(columns.get(col, "") for col in "ABCDEF"))
    if not cells or cells[0] != HEADER:
        raise ValueError("ministry workbook columns changed")
    rows = cells[1:]
    return {
        "sha256": sha256(payload).hexdigest(),
        "declared_range": sheet.find("s:dimension", NS).get("ref"),
        "data_rows": len(rows),
        "columns": list(HEADER),
        "nonempty_contact_rows": sum(bool(r[0]) for r in rows),
        "contact_rows_with_at": sum("@" in r[0] for r in rows),
        "explicit_web_rows": sum(any(EXPLICIT.search(v) for v in r) for r in rows),
        "regions": dict(sorted(Counter(r[3] for r in rows).items())),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("xlsx", type=Path)
    a = p.parse_args()
    print(json.dumps(audit(a.xlsx.read_bytes()), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
