#!/usr/bin/env python3
"""Summarize a sealed GeoSite snapshot by observed transport and application result."""
import argparse
from collections import Counter
import json
from pathlib import Path

from audit import ASNS
from review_baseline import write


def metrics(rows):
    out, states, http, response_scopes = [], Counter(), Counter(), Counter()
    for r in rows:
        if r.get('state') != 'observed':
            continue
        pts = sorted(r['probes'],key=lambda q:q['asn'])
        if [q['asn'] for q in pts] != list(ASNS):
            raise ValueError('unexpected measurement probe set')
        ps = tuple(q['state'] for q in pts)
        codes = tuple(q.get('http') for q in pts)
        tls = tuple(q.get('tls_trusted') is True and q.get('tls_san_match') is True for q in pts)
        flags = set(ps)-{'visible_body_review','body_marker_observed'}
        present = sum(code is not None for code in codes)
        response_scopes[str(present)] += 1
        states.update(ps)
        http['/'.join(str(n) if n is not None else '-' for n in codes)] += 1
        if len(set(ps)) > 1:
            flags.add('asn_disagreement')
        if codes==(200,200,200) and all(tls):
            if all(s=='body_marker_observed' for s in ps):
                flags.add('strong_three_asn_content')
            elif set(ps)<={'visible_body_review','body_marker_observed'}:
                flags.add('visible_content_manual')
        out.append(dict(host=r['host'],url=r['url'],cohort=r['cohort'],id=r['id'],
            http_by_asn='|'.join(f'{a}={c if c is not None else "-"}' for a,c in zip(ASNS,codes)),
            state_by_asn='|'.join(f'{a}={s}' for a,s in zip(ASNS,ps)),
            tls_and_san_by_asn='|'.join(f'{a}={"yes" if t else "not_proven"}' for a,t in zip(ASNS,tls)),
            flags='|'.join(sorted(flags))))
    return out, dict(observed_urls=len(out),probe_order=list(ASNS),http_vectors=http,probe_states=states,
                     urls_by_count_of_http_status=response_scopes,
                     identical_outcome_urls=sum(len(set(x.split('=',1)[1] for x in r['state_by_asn'].split('|')))==1 for r in out))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('sealed',type=Path)
    p.add_argument('out',type=Path)
    a=p.parse_args()
    rows=[json.loads(s) for s in a.sealed.read_text(encoding='utf-8').splitlines()]
    details, info=metrics(rows)
    if not details:
        p.error('no verified GET rows')
    a.out.mkdir(parents=True,exist_ok=False)
    write(a.out/'details.tsv',list(details[0]),details)
    (a.out/'summary.json').write_text(json.dumps(info,sort_keys=True,indent=2,ensure_ascii=False)+'\n')
    print(json.dumps(info,sort_keys=True,ensure_ascii=False))


if __name__=='__main__':
    main()
