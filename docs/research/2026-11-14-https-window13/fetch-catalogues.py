from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit,urljoin
from lxml import html
import subprocess,json,re,sys
d=Path(sys.argv[2]) if len(sys.argv)>2 else Path(__file__).resolve().parent/'sources'
def load(f):return html.fromstring(f.read_text(encoding='utf-8-sig'))
def fetch(row):
 name,url=row;p=d/name
 if p.exists() and p.stat().st_size:return name,0
 tmp=p.with_suffix('.part')
 s=subprocess.run(['curl','-fsSL','--connect-timeout','5','--max-time','12',url,'-o',str(tmp)],capture_output=True,text=True)
 if not s.returncode:tmp.replace(p)
 return name,s.returncode
def collect(rows,workers=5):
 with ThreadPoolExecutor(max_workers=workers) as pool:
  for i,(name,code) in enumerate(pool.map(fetch,rows),1):
   if i%24==0 or code: print(i,name,code,flush=True)
def text(n):return ' '.join(n.text_content().split())
what=sys.argv[1]
if what=='food':
 t=load(d/'prod-russia.html')
 url=next(x for x in t.xpath('//a[contains(@href,"page=")]/@href')).split('?')[0]
 last=max(int(x.split('page=')[-1]) for x in t.xpath('//a[contains(@href,"page=")]/@href'))
 # Cover the alphabetic list evenly rather than just names near the top.
 indexes=sorted({1,last,*range(7,last,6)})
 rows=[(f'prod-russia-{i:03}.html',f'{url}?page={i}') for i in indexes if i!=1]
 collect(rows)
 cards={}
 for i in indexes:
  f=d/(f'prod-russia-{i:03}.html' if i!=1 else 'prod-russia.html')
  if not f.is_file():continue
  for a in load(f).xpath('//a[contains(@href,"/exhibitors/")]'):
   u=a.get('href');key=urlsplit(u).path.split('/')[-1]
   if key.isdecimal():cards.setdefault(key,{'page':i,'url':u,'name':text(a)})
 (d/'food-index.json').write_text(json.dumps({'pages':indexes,'page_total':last,'cards':cards},ensure_ascii=False,indent=2)+'\n')
 print('food pages',len(indexes),'cards',len(cards),flush=True)
 collect([(f'prod-card-{k}.html',row['url']) for k,row in cards.items()])
elif what=='belagro':
 t=load(d/'belagro-ru.html');home='https://belagro-russia.ru/'
 cards={a.get('href').strip('/').split('/')[-1]:{'url':urljoin(home,a.get('href')),'name':text(a)}
       for a in t.xpath('//a[starts-with(@href,"/companies/")]')}
 (d/'belagro-index.json').write_text(json.dumps(cards,ensure_ascii=False,indent=2)+'\n')
 print('belagro cards',len(cards),flush=True)
 collect([(f'belagro-card-{k}.html',row['url']) for k,row in cards.items()],4)

elif what=='astanabuild':
 t=load(d/'astanabuild-iteca.html'); cards={}
 for a in t.xpath('//a[contains(@href,"/details?")]'):
  cs=a.getparent().getparent().xpath('./*[@class="exhib-city"]')
  city=text(cs[0]) if cs else ''
  u=a.get('href')
  q=urlsplit(u).query
  k=q.rsplit('=',1)[-1]
  cards[k]={'country':city.partition(' - ')[0],'city':city,'name':text(a),'url':u,
      'detail':'https://reg.iteca.kz/list/exponent/detailsfull.aspx?'+q}
 (d/'astanabuild-index.json').write_text(json.dumps(cards,ensure_ascii=False,indent=2)+'\n')
 eligible=[(f'astanabuild-card-{k}.html',r['detail']) for k,r in cards.items()
           if r['country'] in {'Казахстан','Россия','Беларусь','Республика Беларусь'}]
 print('astanabuild cards',len(cards),'eligible',len(eligible),flush=True)
 collect(eligible,5)
elif what=='food-regional':
 all_cards={}
 for scope,file in [('BY','prod-by.html'),('KZ','prod-kz.html')]:
  t=load(d/file)
  page_url=f'https://icatalog.expocentr.ru/ru/exhibitions/870c9c18-e84b-11ef-80ce-a0d3c1fab97f/countries/Republic%20of%20{"Belarus" if scope=="BY" else "Kazakhstan"}'
  pmax=max((int(x.split('page=')[-1]) for x in t.xpath('//a[contains(@href,"page=")]/@href')),default=1)
  print(scope,'pages',pmax,flush=True)
  more=[(f'prod-{scope.lower()}-{i:02}.html',f'{page_url}?page={i}') for i in range(2,pmax+1)]
  collect(more,3)
  for path in [d/file,*[d/n for n,_ in more]]:
   if not path.exists():continue
   for a in load(path).xpath('//a[contains(@href,"/exhibitors/")]'):
    u=a.get('href');key=urlsplit(u).path.split('/')[-1]
    if key.isdecimal():all_cards.setdefault(key,{'scope':scope,'url':u,'name':text(a)})
 (d/'food-regional-index.json').write_text(json.dumps(all_cards,ensure_ascii=False,indent=2)+'\n')
 print('regional food',len(all_cards),flush=True)
 collect([(f'prod-card-{k}.html',row['url']) for k,row in all_cards.items()])
elif what=='trans-kz':
 index=json.loads((d/'trans-kz-index.json').read_text())
 region=[(k,r) for k,r in index.items() if r['country'] in {'Россия','Казахстан','Республика Беларусь'}]
 # Sample all BY/RU and every third KZ card. Do not convert mail-domain hints to websites.
 select=[(k,r) for k,r in region if r['country']!='Казахстан']
 select += [(k,r) for k,r in region if r['country']=='Казахстан'][::3]
 (d/'trans-kz-detail-sample.json').write_text(json.dumps(dict(select),ensure_ascii=False,indent=2)+'\n')
 print('detail sample',len(select),flush=True)
 collect([(f'trans-kz-card-{k}.html',r['detail']) for k,r in select],4)
