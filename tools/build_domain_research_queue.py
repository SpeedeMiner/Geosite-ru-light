#!/usr/bin/env python3
"""Produce an actionable, read-only company/domain research queue from the DAT audit.

No external API access, no automated owner attribution, no changes to DIRECT.
"""
import argparse
import csv
from pathlib import Path
from urllib.parse import quote


def read_audit(path: Path):
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.startswith("| `"):
            continue
        cells = [x.strip() for x in raw.strip().strip("|").split("|")]
        if len(cells) != 6:
            raise ValueError(f"{path}:{number}: expected six columns, got {len(cells)}")
        domain, coverage, decision, sources, warning, rationale = cells
        domain = domain.strip("`").lower()
        if not domain or any(ch.isspace() for ch in domain):
            raise ValueError(f"{path}:{number}: invalid domain")
        if coverage == "already_covered_RU" or decision != "unreviewed":
            continue
        if coverage not in ("manual_review_uncovered", "uncovered_with_upstream_warning"):
            continue
        yield domain, coverage, decision, sources, warning, rationale


def url_for(domain: str, service: str) -> str:
    # crt.sh supports 'q'; ICANN/Netlas links are deliberately general entry points.
    if service == "ct":
        return "https://crt.sh/?q=" + quote(domain, safe="")
    if service == "rdap":
        return "https://lookup.icann.org/en/lookup"
    if service == "netlas":
        return "https://app.netlas.io/"
    raise ValueError(service)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("audit", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    rows = sorted(read_audit(args.audit), key=lambda v: (v[1] != "manual_review_uncovered", v[0]))
    if not rows:
        raise SystemExit("empty uncovered and unreviewed research queue")
    with args.output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow(["domain", "priority", "coverage_status", "sources", "upstream_warning",
                         "ct_search", "rdap_lookup", "netlas_research", "next_step"])
        for domain, coverage, _, sources, warning, _ in rows:
            priority = "P1" if coverage == "manual_review_uncovered" else "P2"
            next_step = ("Verify owner on first-party company page or public registrant data; "
                         "verify purpose and smallest permissible Full/Root scope")
            writer.writerow([domain, priority, coverage, sources, warning,
                             url_for(domain, "ct"), url_for(domain, "rdap"),
                             url_for(domain, "netlas"), next_step])
    p1 = sum(c == "manual_review_uncovered" for _, c, *_ in rows)
    p2 = len(rows) - p1
    print(f"DOMAIN_RESEARCH_QUEUE total={len(rows)} P1={p1} P2={p2} output={args.output}")
    print("RESEARCH QUEUE IS EVIDENCE-ONLY; NO AUTOMATIC DIRECT IMPORT")


if __name__ == "__main__":
    main()
