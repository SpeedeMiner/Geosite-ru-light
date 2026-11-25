#!/usr/bin/env python3
"""Summarize observed coverage, including absent or incomplete batches."""
import collections, json
from pathlib import Path

root=Path('vpn-results'); plan=Path('vpn-plan')
manifest=json.loads((plan/'manifest.json').read_text(encoding='utf-8'))
observed=collections.defaultdict(list); jobs=[]
for n in range(manifest['batch_count']):
    folder=root/f'vpn-shard-{n}'
    summaries=list(folder.rglob('geosite-vpnobratno-summary.json'))
    observations=list(folder.rglob('vpnobratno-observations.jsonl'))
    job={'batch':n,'summaries':[json.loads(p.read_text(encoding='utf-8')) for p in summaries],'observation_files':len(observations)}
    jobs.append(job)
    for obs in observations:
        for line in obs.read_text(encoding='utf-8').splitlines():
            r=json.loads(line); observed[r['host']].append(r)
results=[]
for host,rules in manifest['hosts_to_rules'].items():
    entries=observed.get(host,[]); asns=sorted({r['vpn_asn'] for r in entries if r.get('vpn_country')=='RU' and r.get('vpn_asn') and r.get('verified_by_sources',0)>=2 and not r.get('asn_conflict')})
    results.append({'hostname':host,'rules':rules,'verified_asns':asns,'coverage':'two_or_more_asns' if len(asns)>=2 else 'one_asn' if asns else 'not_tested','observations':entries})
counts=dict(collections.Counter(r['coverage'] for r in results))
out={'sha256':manifest['sha256'],'rules':manifest['rule_count'],'testable_hosts':manifest['host_count'],'not_applicable':manifest['not_applicable'],'coverage':counts,'jobs':jobs,'hosts':results}
Path('vpn-coverage').mkdir(exist_ok=True)
Path('vpn-coverage/report.json').write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf-8')
summary=f"# VPN full-list coverage\n\nDAT: `{manifest['sha256']}`  \nRules: {manifest['rule_count']}; eligible unique FQDNs: {manifest['host_count']}  \nCoverage: `{json.dumps(counts)}`\n\nOne hostname may correspond to multiple rules. Root zones and uncheckable rule types are listed separately in report.json. Observed RU VPN ASN is not a home-line guarantee. A timeout, DNS failure or 403 is not evidence for deletion. Results are IPv4-only; adapter does not follow redirects.\n"
Path('vpn-coverage/report.md').write_text(summary,encoding='utf-8')
print(summary)

if __name__=='__main__': pass
