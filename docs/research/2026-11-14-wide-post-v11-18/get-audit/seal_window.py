#!/usr/bin/env python3
"""Seal a declared GET batch with resume state and safe evidence, without network."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
from urllib.parse import urlsplit

from audit import ASNS
from catalog_009 import evidence
from prepare import FIELDS, SERVER_V1118, hostname, records, ru
from report_008 import BY_HOST, BY_REDIRECT, check_result, scrub_redirects
from review_baseline import light_categories, matches, triage, write


def seal(audit, plans, observation, light_path, server_path, out):
    light = light_categories(light_path)
    server_set = ru(server_path, SERVER_V1118)
    server = {k:{v for x,v in server_set if x==k} for k in (2,3)}
    saved = evidence(audit)
    old = {u:r for u,r in saved.items() if u not in plans}
    known_ids = {r['id'] for r in old.values()}
    baseline = {r['host']:r['url'] for r in records(audit/'baseline-exact.tsv')}
    prior_roots = {r['host'] for r in old.values()
                   if r['cohort']=='baseline' and baseline.get(r['host'])==r['url']}
    logged = {}
    for line in observation.read_text(encoding='utf-8').splitlines():
        r = json.loads(line)
        if r['url'] in logged:
            raise ValueError(f"duplicate result in batch: {r['url']}")
        check_result(r, plans, known_ids)
        r = scrub_redirects(r)
        if r['url'] in saved and saved[r['url']] != r:
            raise ValueError(f"saved evidence differs for {r['url']}")
        logged[r['url']] = r
    if any(url in saved and url not in logged for url in plans):
        raise ValueError('saved observation absent from this snapshot')

    details, redirects, todo, started_pending = [], [], [], []
    new_roots = set()
    status, cohorts = Counter(), defaultdict(Counter)
    for url,(batch,p) in plans.items():
        h = p['host']
        if p['cohort']=='baseline' and (baseline.get(h)!=url or h in prior_roots):
            raise ValueError(f'invalid root baseline row: {url}')
        r = logged.get(url, {})
        state = r.get('state','no_result_received')
        status[state] += 1
        cohorts[p['cohort']][state] += 1
        if state == 'observed':
            if p['cohort']=='baseline':
                new_roots.add(h)
        elif r.get('id'):
            started_pending.append(dict(p,id=r['id'],state=state))
        else:
            todo.append(p)
        pts = sorted(r.get('probes',[]),key=lambda q:q['asn'])
        details.append(dict(batch=batch,cohort=p['cohort'],host=h,url=url,measurement_id=r.get('id',''),
            measurement_state=state,http_by_asn='|'.join(f"{q['asn']}={q.get('http') or '-'}" for q in pts),
            probe_states='|'.join(f"{q['asn']}={q['state']}" for q in pts),
            triage=triage(pts) if state=='observed' else 'not_verified',source=p['source'],
            current_light_ru='yes' if matches(light['RU'],h) else 'no',
            current_server_ru='yes' if matches(server,h) else 'no',
            current_light_block='yes' if matches(light['BLOCK'],h) else 'no'))
        if state != 'observed':
            continue
        groups = defaultdict(set)
        for q in pts:
            dest = q.get('redirect_location')
            if q['state'] != 'redirect_observed' or not dest:
                continue
            rh = urlsplit(dest).hostname
            if not rh or rh != q.get('redirect_host'):
                raise ValueError(f'invalid redirect evidence: {url}')
            groups[(rh,dest)].add(q['asn'])
        for (rh,dest),probes in sorted(groups.items()):
            redirects.append(dict(source_host=h,source_url=url,target_host=rh,target_url=dest,
                asns='|'.join(map(str,sorted(probes))),measurement_id=r['id'],
                light_categories='|'.join(sorted(c for c,v in light.items() if matches(v,rh))) or '-',
                server_ru='yes' if matches(server,rh) else 'no'))
    out.mkdir(parents=True,exist_ok=False)
    with (out/'live-observations.jsonl').open('x',encoding='utf-8') as f:
        for u in plans:
            if u in logged:
                print(json.dumps(logged[u],ensure_ascii=False,separators=(',',':')),file=f)
    write(out/'outcomes.tsv',BY_HOST,details)
    write(out/'redirects.tsv',BY_REDIRECT,redirects)
    write(out/'not-started.tsv',FIELDS,todo)
    write(out/'started-pending.tsv',(*FIELDS,'id','state'),started_pending)
    base_pending = [r for r in records(audit/'baseline-exact.tsv') if r['host'] not in prior_roots|new_roots]
    write(out/'baseline-pending.tsv',FIELDS,base_pending)
    summary=dict(planned=len(plans),recorded=len(logged),verified_get4=status['observed'],
                 verified_probes=len(ASNS)*status['observed'],measurement_ids=sum(bool(r.get('id')) for r in logged.values()),
                 states=status,by_cohort=cohorts,baseline_new=len(new_roots),baseline_prior=len(prior_roots),
                 baseline_total=len(baseline),baseline_verified=len(prior_roots|new_roots),baseline_pending=len(base_pending),
                 not_started=len(todo),started_pending=len(started_pending),redirect_rows=len(redirects))
    (out/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2,sort_keys=True)+'\n')
    return summary


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('plan',type=Path)
    p.add_argument('observations',type=Path)
    p.add_argument('light',type=Path)
    p.add_argument('server',type=Path)
    p.add_argument('output',type=Path)
    a=p.parse_args()
    audit=Path(__file__).resolve().parent
    rows=records(a.plan)
    if not rows or len(rows)!=len({r['url'] for r in rows}) or any(hostname(r['url'])!=r['host'] for r in rows):
        p.error('expected unique public HTTPS rows')
    plans={r['url']:(a.plan.stem,r) for r in rows}
    info=seal(audit,plans,a.observations,a.light,a.server,a.output)
    print(json.dumps(info,ensure_ascii=False,sort_keys=True))


if __name__=='__main__':
    main()
