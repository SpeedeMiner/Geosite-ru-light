"""Preserve the unattempted queue and the individually deferred measurements."""
import csv
from pathlib import Path
import sys

base=Path('repo/docs/research')
root=base/'2026-11-14-https-window2'
def rows(path):
 with path.open() as f: return list(csv.DictReader(f,delimiter='\t'))
def write(path,data,fields):
 with path.open('x') as f:
  w=csv.DictWriter(f,fields,delimiter='\t',lineterminator='\n',extrasaction='ignore')
  w.writeheader()
  w.writerows(data)

dec={r['host']:r for r in rows(root/sys.argv[1])}
label=sys.argv[2] if len(sys.argv)>2 else '99'
original=rows(base/'2026-11-14-halfhour/12-next-https.tsv')
new_plan={r['host']:r for n in ('01-priority-plan.tsv','02-second-plan.tsv','05-reserve-plan.tsv') for r in rows(root/n)}
queued=[]
holds=[]
for r in original:
 d=dec.get(r['host'])
 new=new_plan.get(r['host'])
 if not d or (d['decision']=='hold_measurement' and not d['id']):
  if new:
   r.update(https_path=new['url'],source=new['primary'],note=new['operator'])
  queued.append(r)
 elif d['decision']!='accept':
  holds.append(d)
write(root/f'{label}-remaining-unmeasured.tsv',queued,original[0].keys())
if holds:
 write(root/f'{label}-measured-holds.tsv',holds,holds[0].keys())
print('unmeasured',len(queued),'holds',len(holds),'accepted',sum(d['decision']=='accept' for d in dec.values()))
