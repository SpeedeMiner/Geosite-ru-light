from pathlib import Path
from lxml import html
from importlib.util import spec_from_file_location,module_from_spec
from collections import Counter
from hashlib import sha256
import csv,re,json,subprocess
import argparse
cli=argparse.ArgumentParser()
cli.add_argument("sources",type=Path)
cli.add_argument("dat",type=Path)
cli.add_argument("out",type=Path)
a=cli.parse_args()
d=a.sources
p=Path('docs/research/2026-11-14-https-window12')
s=spec_from_file_location('audit',p/'audit-catalogues.py')
m=module_from_spec(s);s.loader.exec_module(m)
dat=a.dat
c=m.G.memberships(dat.read_bytes())
t=m.document(d/'wood-list.html')
table=t.xpath('//*[contains(@class,"template-page-content-expo")]//table')[0]
rows=[[m.plain(x) for x in tr.xpath('./td|./th')] for tr in table.xpath('.//tr')]
assert len(rows)==34 and all(len(row)==5 for row in rows)
m.write(a.out,"04-woodworking-exhibitors.tsv",['exhibitor','country'],[dict(exhibitor=x[0],country=x[1]) for x in rows])
pdf=d/'wood-catalogue.pdf'
raw=subprocess.check_output(['pdftotext','-layout',str(pdf),'-'],text=True)
urls=[]
pattern=re.compile(r'(?iu)(?:https?://\s*(?:www\.)?|www\.)([\w.-]+\.[a-zа-яё]{2,})(?:/[^\s,]*)?')
for page,body in enumerate(raw.split('\f'),1):
 for i,line in enumerate(body.splitlines(),1):
  for x in pattern.finditer(line):
   u=re.sub(r'(?<=://)\s+','',x[0])
   host=m.normalize(u)
   if not host: continue
   coverage=','.join(k for k,v in c.items() if any(m.G.REPLAY.match(host,r) for r in v)) or 'uncovered'
   section='Автосервис' if page>=33 else 'Деревообработка'
   urls.append(dict(page=page,line=i,section=section,website=u,host=host,coverage=coverage))
assert len({r['host'] for r in urls})==len(urls)
m.write(a.out,"04-woodworking-pdf-coverage.tsv",list(urls[0]),urls)
print(len(rows),Counter(x[1] for x in rows),len(urls),Counter(r['coverage'] for r in urls))
print('pdf',m.digest(pdf),'list',m.digest(d/'wood-list.html'))
