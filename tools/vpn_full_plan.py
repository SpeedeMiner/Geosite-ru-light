#!/usr/bin/env python3
"""Create a complete, reproducible inventory for bounded VPN jobs."""
import csv, hashlib, io, json, math, os, urllib.request
from pathlib import Path
from publicsuffix2 import PublicSuffixList
from audit_ru_liveness import extract, applicable

BASE='https://github.com/SpeedeMiner/Geosite-ru-light/releases/download/latest-optimized/'
EXPECTED='027939e3a31591bd48a57428c893a8237fe61352d90a8c3077b39366a3a3d0cc'

def get(url):
    return urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'Geosite-RU-audit'}),timeout=60).read()

def main():
    output=Path('vpn-plan'); output.mkdir(exist_ok=True)
    data=get(BASE+'geosite_RU.dat'); side=get(BASE+'geosite_RU.dat.sha256sum').decode().split()[0].lower()
    sha=hashlib.sha256(data).hexdigest()
    if sha!=side or sha!=EXPECTED: raise ValueError('DAT checksum or audited release changed')
    psl=PublicSuffixList(io.StringIO(get('https://publicsuffix.org/list/public_suffix_list.dat').decode()))
    rules=extract(data); names={}; skipped=[]
    for r in rules:
        ok,host=applicable(r,psl)
        if not ok: skipped.append(dict(r,reason=host)); continue
        names.setdefault(host,[]).append(r)
    ordered=sorted(names); batch_size=100; batches=math.ceil(len(ordered)/batch_size)
    if batches>256: raise ValueError('GitHub matrix exceeds 256 jobs')
    for n in range(batches):
        batch=ordered[n*batch_size:(n+1)*batch_size]
        with (output/f'batch-{n:03d}.tsv').open('w',encoding='utf-8',newline='') as f:
            w=csv.DictWriter(f,fieldnames=['cohort','type','rule','host','url','markers','source'],delimiter='\t'); w.writeheader()
            for host in batch:
                r=names[host][0]; w.writerow(dict(cohort='audit',type=r['type'],rule=r['value'],host=host,url='https://'+host+'/',markers='',source='verified rolling DAT'))
    manifest={'sha256':sha,'rule_count':len(rules),'host_count':len(ordered),'batch_size':batch_size,'batch_count':batches,'hosts_to_rules':names,'not_applicable':skipped}
    (output/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    batches_out=list(range(batches))
    if os.environ.get('VPN_SMOKE')=='1': batches_out=batches_out[:1]
    with open(os.environ['GITHUB_OUTPUT'],'a',encoding='utf-8') as f: f.write('batches='+json.dumps(batches_out)+'\n')
    print(json.dumps({k:manifest[k] for k in ('sha256','rule_count','host_count','batch_size','batch_count')}))

if __name__=='__main__': main()
