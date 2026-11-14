"""Show candidate evidence for the manual approval journal, never approve it."""
import csv
import json
from pathlib import Path
import sys
rows={}
for file in sys.argv[1:]:
 for line in Path(file).read_text().splitlines():
  row=json.loads(line)
  if row['state']=='https_candidate':
   rows[row['host']]=row
w=csv.writer(sys.stdout,delimiter='\t',lineterminator='\n')
w.writerow(['host','id','title','minimum_visible_chars','markers','rationale'])
for host,r in sorted(rows.items()):
 probes=r['probes']
 title=' | '.join(dict.fromkeys(x['title'] for x in probes if x['title']))
 marks=' | '.join(dict.fromkeys(','.join(x['markers']) for x in probes))
 w.writerow([host,r['id'],title,min(x['visible_chars'] for x in probes),marks,''])
