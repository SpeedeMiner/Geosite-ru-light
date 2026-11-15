#!/usr/bin/env python3
"""Seal GeoSite GET window 008, keeping unobserved rows and redirects distinct."""
import argparse
from collections import Counter, defaultdict
from pathlib import Path
import json
from urllib.parse import urlsplit, urlunsplit

from audit import ASNS, SAFE_ID
from prepare import FIELDS, SERVER_V1118, records, ru
from prepare_wide_window import load_live
from review_baseline import light_categories, matches, triage, write

BATCHES = ('regional','wide007','functional','baseline006a')
BY_HOST = ('batch','cohort','host','url','measurement_id','measurement_state','http_by_asn',
           'probe_states','triage','current_light_ru','current_server_ru','current_light_block','source')
BY_REDIRECT = ('source_host','source_url','target_host','target_url','asns','light_categories',
               'server_ru','measurement_id')


def scrub_redirects(row):
    for p in row.get('probes',[]):
        value = p.get('redirect_location')
        if value:
            u = urlsplit(value)
            if u.username or u.password or u.query or u.fragment:
                p['redirect_location'] = urlunsplit((u.scheme, u.hostname or '', u.path,'',''))
                p['redirect_details_omitted'] = True
    return row


def check_result(row, plan, ids):
    url = row['url']
    if url not in plan or any(row.get(k)!=plan[url][1][k] for k in FIELDS):
        raise ValueError(f'output row differs from plan for {url}')
    if (row.get('test'),row.get('requested_family'))!=('get',4):
        raise ValueError(f'wrong test or address family for {url}')
    mid = row.get('id')
    if mid:
        if not isinstance(mid,str) or not SAFE_ID.fullmatch(mid) or mid in ids:
            raise ValueError('invalid or duplicate measurement id')
        ids.add(mid)
    if row.get('state')=='observed':
        probes = row.get('probes',[])
        if (not mid or len(probes)!=3 or {p['asn'] for p in probes}!=set(ASNS)
                or any(p.get('country')!='RU' or p.get('redirect_followed',False) for p in probes)
                or row.get('probe_states')!=Counter(p['state'] for p in probes)):
            raise ValueError(f'inconsistent observed probe set for {url}')


def run(audit, evidence, light_dat, server_dat, output):
    l = light_categories(light_dat)
    server_rules = ru(server_dat,SERVER_V1118)
    s = {k:{v for t,v in server_rules if t==k} for k in (2,3)}
    previous, _ = load_live(audit)
    plans, meta = {}, {}
    for batch in BATCHES:
        rows = records(audit/'wide-008'/f'{batch}.tsv')
        for r in rows:
            if r['url'] in plans or r['url'] in previous:
                raise ValueError(f'overlap on {r["url"]}')
            plans[r['url']] = batch,r
    for f in ('wide-008/coverage.tsv','wide-007/coverage.tsv'):
        meta.update({r['url']:r for r in records(audit/f)})
    ids = {r['id'] for r in previous.values() if r.get('id')}
    logged = {}
    for raw in evidence.read_text(encoding='utf-8').splitlines():
        try:
            row=json.loads(raw)
        except json.JSONDecodeError:
            # Caller supplies an immutable snapshot ending at a complete line.
            raise ValueError('window evidence includes a partial JSON line') from None
        if row['url'] in logged:
            raise ValueError(f'duplicate result URL {row["url"]}')
        check_result(row,plans,ids)
        logged[row['url']]=scrub_redirects(row)

    named, redirects, queued = [], [], []
    by_cohort, by_batch = defaultdict(Counter), defaultdict(Counter)
    overall = Counter()
    sectors = set()
    for url,(batch,p) in plans.items():
        r=logged.get(url,{})
        state=r.get('state','no_result_received')
        overall[state]+=1
        by_batch[batch][state]+=1
        by_cohort[p['cohort']][state]+=1
        if state!='observed':
            queued.append(p)
        probes=sorted(r.get('probes',[]),key=lambda x:x.get('asn') or 0)
        host=p['host']
        if state=='observed' and url in meta:
            sectors.add(meta[url]['sector'])
        named.append(dict(batch=batch,cohort=p['cohort'],host=host,url=url,measurement_id=r.get('id',''),
                          measurement_state=state,http_by_asn='|'.join(f'{x.get("asn")}={x.get("http") or "-"}' for x in probes),
                          probe_states='|'.join(f'{x.get("asn")}={x.get("state")}' for x in probes),
                          triage=triage(probes) if state=='observed' else 'not_verified',
                          current_light_ru='yes' if matches(l['RU'],host) else 'no',
                          current_server_ru='yes' if matches(s,host) else 'no',
                          current_light_block='yes' if matches(l['BLOCK'],host) else 'no',source=p['source']))
        if state=='observed':
            grouped=defaultdict(set)
            for x in probes:
                if x.get('state')=='redirect_observed' and x.get('redirect_host') and x.get('redirect_location'):
                    to=urlsplit(x['redirect_location'])
                    if to.hostname!=x['redirect_host']:
                        raise ValueError(f'inconsistent redirect target for {url}')
                    grouped[(to.hostname,urlunsplit((to.scheme,to.hostname,to.path,'','')))].add(x['asn'])
            for (target,dest),asn in sorted(grouped.items()):
                categories='|'.join(sorted(c for c,v in l.items() if matches(v,target))) or '-'
                redirects.append(dict(source_host=host,source_url=url,target_host=target,target_url=dest,
                                      asns='|'.join(map(str,sorted(asn))),light_categories=categories,
                                      server_ru='yes' if matches(s,target) else 'no',measurement_id=r['id']))

    backlog=records(audit/'pending-baseline-after-005.tsv')
    backlog_set={r['host'] for r in backlog}
    exact=set(r['host'] for r in named if r['cohort']=='baseline' and r['measurement_state']=='observed')
    if not exact.issubset(backlog_set):
        raise ValueError('new baseline result is not in the backlog')
    prior=int(len(l['RU'][3])-len(backlog))
    remaining=[r for r in backlog if r['host'] not in exact]
    output.mkdir(parents=True,exist_ok=False)
    with (output/'live-observations.jsonl').open('x',encoding='utf-8') as f:
        for p in plans:
            if p in logged:
                print(json.dumps(logged[p],ensure_ascii=False,separators=(',',':')),file=f)
    write(output/'outcomes.tsv',BY_HOST,named)
    write(output/'redirects.tsv',BY_REDIRECT,redirects)
    write(output/'window-pending.tsv',FIELDS,queued)
    write(output/'baseline-pending.tsv',FIELDS,remaining)
    done = overall.get('observed',0)
    summary=dict(planned=len(plans),recorded=len(logged),verified_gets=done,verified_probe_records=done*3,
                 measurement_ids=sum(1 for r in logged.values() if r.get('id')),states=overall,
                 by_batch=by_batch,by_cohort=by_cohort,triage=Counter(r['triage'] for r in named),
                 redirect_rows=len(redirects),metadata_sectors_observed=len(sectors),
                 baseline_new=len(exact),baseline_verified=prior+len(exact),baseline_pending=len(remaining))
    with (output/'summary.json').open('x',encoding='utf-8') as f:
        print(json.dumps(summary,ensure_ascii=False,indent=2,sort_keys=True),file=f)
    return summary


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('evidence',type=Path)
    p.add_argument('light',type=Path)
    p.add_argument('server',type=Path)
    p.add_argument('output',type=Path)
    a=p.parse_args()
    print(json.dumps(run(Path(__file__).resolve().parent,a.evidence,a.light,a.server,a.output),ensure_ascii=False,sort_keys=True))
