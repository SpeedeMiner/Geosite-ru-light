#!/usr/bin/env python3
"""Verify VPN pool run artifacts and count each URL and ASN exactly once."""
import argparse
from collections import Counter, defaultdict
import hashlib
from ipaddress import ip_address
import json
from pathlib import Path
from zipfile import ZipFile

from prepare import records
from vpn_pool import BASELINE, POOL, ROOT, write
from vpnobratno_get import TRANSPORT, UPSTREAM_REF, rc_ok


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verified_batch(path, meta, plan, batch):
    digest = meta['digest'].removeprefix('sha256:')
    require(sha256(path) == digest, f'batch {batch}: archive digest mismatch')
    require(path.stat().st_size < 2_000_000, f'batch {batch}: unexpected archive size')
    with ZipFile(path) as archive:
        require(sum(f.file_size for f in archive.infolist()) < 5_000_000, 'expanded archive too large')
        require(archive.testzip() is None, f'batch {batch}: corrupt ZIP')
        summary = json.loads(archive.read('geosite-vpnobratno-summary.json'))
        transport = json.loads(archive.read('vpn_gate_summary.json'))
        data = ('vpnobratno-observations.jsonl' in archive.namelist()
                and archive.read('vpnobratno-observations.jsonl').splitlines()) or []
    require(transport['selected_source']=='vpnobratno' and
            transport['execution_sha']==meta['sha'] and transport['workflow_run_id']==str(meta['run_id']) and
            transport['workflow_run_attempt']==str(meta['attempt']), f'batch {batch}: bad provenance')
    require(summary['upstream_ref']==UPSTREAM_REF and summary['transport']==TRANSPORT
            and not summary['fresh_ru_credit'] and summary['globalping_requests']==0,
            f'batch {batch}: wrong backend or scope')
    require(len(plan)==summary['requested_urls'] and summary['requested_exits']==2
            and len(data)==summary['measurements'], f'batch {batch}: wrong target or result count')
    exits=defaultdict(list)
    for line in data:
        row=json.loads(line)
        asn=row['vpn_asn']
        require(row['url'] in plan and row['host']==plan[row['url']]['host']
                and row['http_method']=='GET' and row['test']=='vpn_get'
                and row['scope']=='vpnobratno_observed_egress'
                and row['transport']==TRANSPORT and row['upstream_ref']==UPSTREAM_REF
                and row['vpn_country']=='RU' and row['verified_by_sources']>=2
                and row['asn_conflict'] is False and not row['redirect_followed']
                and not row['fresh_ru_credit'] and type(asn) is int and asn>0
                and {int(row[k]) for k in ('asn_ip_metadata','asn_ripestat') if row[k]}=={asn},
                f'batch {batch}: invalid observation for {row["url"]}')
        ip=ip_address(row['vpn_exit_ip'])
        require(ip.version==4 and ip.is_global and not ip.is_multicast, 'invalid egress')
        exits[asn].append(row)
    require(len(exits)==summary['distinct_exit_asns']<=2, f'batch {batch}: invalid ASN count')
    for asn, rows in exits.items():
        urls=[r['url'] for r in rows]
        require(len(set(urls))==len(urls) and urls==[u for u in plan if u in urls]
                and len({r['vpn_exit_ip'] for r in rows})==1, f'batch {batch}: inconsistent exit or URL')
        [s]=[x for x in summary['verified_exits'] if x['asn']==asn]
        require(s['urls']==len(rows) and s['ip']==rows[0]['vpn_exit_ip'] and
                s['http_responses']==sum(bool(r['http']) and rc_ok(r) for r in rows),
                f'batch {batch}: mismatched ASN summary')
    require(summary['http_responses']==sum(bool(r['http']) and rc_ok(r) for rows in exits.values() for r in rows),
            f'batch {batch}: HTTP summary mismatch')
    return exits, summary, digest


def seal(plans, archives, output):
    manifest=json.loads((plans/'manifest.json').read_text(encoding='utf-8'))
    index=json.loads((archives/'index.json').read_text(encoding='utf-8'))
    for rel,digest in manifest['pool_sha256'].items():
        require(sha256(ROOT/rel)==digest, f'pinned input changed: {rel}')
    pool={r['url']:r for rel in POOL for r in records(ROOT/rel)}
    require(len(pool)==manifest['queued'], 'pool size differs from manifest')
    observations=defaultdict(list)
    for rel in BASELINE:
        run=Path(rel).stem.removeprefix('run-')
        for r in records(ROOT/rel):
            if r['url'] not in pool or r['tls']!='verified' or not r['http']:
                continue
            require(r['exit_country']=='RU', 'unexpected baseline country')
            observations[r['url']].append(dict(r,run=run,batch='pilot'))
    prior={url for url,rows in observations.items() if len({r['exit_asn'] for r in rows})>=2}
    require(len(prior)==manifest['reused'], 'unexpected baseline size')
    assigned={}
    receipts=[]
    for batch in manifest['batches']:
        plan={r['url']:r for r in records(plans/f'batch-{batch}.tsv')}
        require(not (set(assigned)|prior)&plan.keys() and plan.keys()<=pool.keys(), f'bad plan batch {batch}')
        assigned.update({u:batch for u in plan})
        for meta in index.get(batch,[]):
            path=archives/f"{meta['artifact_id']}.zip"
            exits,summary,digest=verified_batch(path,meta,plan,batch)
            receipts.append(dict(batch=batch,run_id=meta['run_id'],run_attempt=meta['attempt'],
                                 artifact_id=meta['artifact_id'],artifact_zip_sha256=digest,
                                 execution_sha=meta['sha'],globalping_requests=0,
                                 measurements=summary['measurements'],http_responses=summary['http_responses'],
                                 upstream_state=summary['upstream_state'],
                                 asns=sorted(exits),connection_attempts=summary['connection_attempts']))
            for asn, rows in exits.items():
                for r in rows:
                    observations[r['url']].append(dict(url=r['url'],http=r['http'] or '',
                        tls='verified' if r['http'] and rc_ok(r) else 'unproven',
                        state=r['state'],exit_asn=asn,exit_country='RU',redirect=r['redirect_location'] or '',
                        marker='|'.join(r['markers_found']),observed_at=r['observed_at'],
                        run=meta['run_id'],batch=batch))
    require(set(pool)==set(assigned)|prior and len(assigned)==manifest['pending'], 'plan coverage mismatch')
    detail=[]
    coverage=[]
    differences=[]
    for url,source in pool.items():
        all_rows=observations[url]
        detail.extend(all_rows)
        # Count across ASNs, not IPs, repeated runs or matching status codes.
        best={}
        for r in sorted(all_rows,key=lambda r:(r['tls']=='verified',r['observed_at'])):
            best[int(r['exit_asn'])]=r
        good={asn:r for asn,r in best.items() if r['tls']=='verified'}
        fingerprints={(r['http'],r['state'],r['redirect'],r['marker']) for r in good.values()}
        row=dict(url=url,host=source['host'],type=source['type'],batch=assigned.get(url,'pilot'),
                 attempted_asns=len(best),verified_http_asns=len(good),
                 verified_2xx_asns=sum(200<=int(r['http'])<300 for r in good.values()),
                 asns='|'.join(map(str,sorted(best))),outcomes='|'.join(
                     f"AS{a}={best[a]['http'] or '-'}/{best[a]['state']}" for a in sorted(best)),
                 comparison='different' if len(fingerprints)>1 else 'same' if len(good)>1 else 'insufficient')
        coverage.append(row)
        if row['comparison']=='different':
            differences.append(row)
    pending=[r for r in coverage if r['attempted_asns']<2]
    unresolved=[r for r in coverage if r['verified_http_asns']<2]
    stats=dict(pool_urls=len(pool),prior_urls=len(prior),new_planned=len(assigned),batch_artifacts=len(receipts),
               verified_http_by_url_asn=dict(sorted(Counter(r['verified_http_asns'] for r in coverage).items())),
               attempts_by_url_asn=dict(sorted(Counter(r['attempted_asns'] for r in coverage).items())),
               total_get_observations=len(detail),http_verified_observations=sum(r['tls']=='verified' for r in detail),
               asns=sorted({int(r['exit_asn']) for r in detail}),different_http_outcomes=len(differences),
               missing_second_attempt=len(pending),needs_http_followup=len(unresolved),
               new_attempted_urls=sum(r['attempted_asns']>0 and r['batch']!='pilot' for r in coverage),
               observation_states=dict(sorted(Counter(r['state'] for r in detail).items())),
               globalping_requests=0,fresh_ru_credit=False)
    output.mkdir(parents=True,exist_ok=False)
    write(output/'coverage.tsv',list(coverage[0]),coverage)
    write(output/'observations.tsv',['url','http','state','tls','exit_asn','exit_country','redirect','marker','observed_at','run','batch'],detail)
    write(output/'different.tsv',list(coverage[0]),differences)
    write(output/'needs-http-followup.tsv',list(coverage[0]),unresolved)
    write(output/'needs-second-attempt.tsv',list(coverage[0]),pending)
    (output/'summary.json').write_text(json.dumps(stats,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    (output/'receipts.json').write_text(json.dumps(receipts,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    return stats


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('plans',type=Path)
    p.add_argument('archives',type=Path)
    p.add_argument('output',type=Path)
    a=p.parse_args()
    print(json.dumps(seal(a.plans,a.archives,a.output),ensure_ascii=False))
