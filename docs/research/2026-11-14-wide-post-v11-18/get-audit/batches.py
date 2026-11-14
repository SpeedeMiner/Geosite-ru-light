#!/usr/bin/env python3
"""Split exact-release inventory into bounded, deterministic, nonoverlapping plans."""
import argparse
from pathlib import Path
from prepare import FIELDS,records,write

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("inventory",type=Path)
    p.add_argument("out",type=Path)
    p.add_argument("--exclude",action="append",type=Path,default=[])
    p.add_argument("--size",type=int,default=50,choices=range(1,84))
    a=p.parse_args()
    skip={r["host"] for f in a.exclude for r in records(f) if r.get("cohort")=="baseline"}
    rows=records(a.inventory)
    if not rows or any(r["cohort"]!="baseline" or r["type"]!="full" or r["rule"]!=r["host"] for r in rows):
        p.error("expected exact baseline inventory")
    if len(rows)!=len({r["host"] for r in rows}):p.error("duplicate baseline host")
    rows=sorted((r for r in rows if r["host"] not in skip),key=lambda r:r["host"])
    a.out.mkdir(parents=True)
    for i in range(0,len(rows),a.size):
        write(a.out/f"baseline-{i//a.size+1:03d}.tsv",FIELDS,rows[i:i+a.size])
    print(f"{len(rows)} exact hosts in {(len(rows)+a.size-1)//a.size} batches")
if __name__=="__main__":main()
