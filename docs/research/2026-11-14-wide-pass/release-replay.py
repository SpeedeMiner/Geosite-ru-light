#!/usr/bin/env python3
"""Rebuild this research candidate directly from the verified release GeoSite DAT."""
import argparse,hashlib,importlib.util,re
from pathlib import Path

LIGHT_V11_17='75b79f1883e0ae7380621c41bdac89777dc1df660844d141ea98a400526728ec'
SERVER_V11_17='d62ce50c0e383bf6a252fd5ed69169bb9de870c9e1ce8821100458118f20ec34'
LABEL=re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
def match(n,entry):
 typ,value=entry
 if typ==3:return n==value
 if typ==2:return n==value or n.endswith('.'+value)
 if typ==1:return re.search(value,n) is not None
 if typ==0:return value in n
 raise ValueError('unsupported domain type')
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('light','server','rules','server_repo','output'):
  p.add_argument(name,type=Path)
 a=p.parse_args()
 f=a.server_repo/'tools/project_geosite.py'
 spec=importlib.util.spec_from_file_location('server_projection',f)
 if spec is None or spec.loader is None:raise SystemExit(f'cannot import {f}')
 s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
 l,b=a.light.read_bytes(),a.server.read_bytes()
 if sha(l)!=LIGHT_V11_17 or sha(b)!=SERVER_V11_17:raise SystemExit('input release SHA-256 mismatch')
 policy=a.server_repo/'data'
 if not (policy/'exclude-server-suffixes.txt').is_file():
  policy=a.server_repo
 deny,keep=(s.policy_list(policy/n) for n in ('exclude-server-suffixes.txt','retain-server-suffixes.txt'))
 if s.project(l,deny,keep)[0]!=b:raise SystemExit('release Server cannot be reconstructed from release Light')
 rules=[]
 for row in a.rules.read_text().splitlines():
  r=row.strip()
  if not r or r.startswith('#'):continue
  h=r.removeprefix('full:')
  if not r.startswith('full:') or '.' not in h or len(h)>253 or not all(LABEL.fullmatch(q) for q in h.split('.')):
   raise SystemExit(f'bad rule {r!r}')
  rules.append(h)
 if len(set(rules))!=len(rules):raise SystemExit('duplicate candidate rules')
 def categories(bs):
  d={}
  for typ,site in s.fields(bs):
   if typ!=1 or not isinstance(site,bytes):raise ValueError('invalid GeoSiteList')
   e=list(s.fields(site)); name=dict(e)[1]
   if name in d:raise ValueError('duplicate category')
   d[name]=(site,e)
  return d
 def decoded(e):
  for k,d in e:
   if k==2:
    item=dict(s.fields(d));yield item.get(1,0),item[2].decode('ascii')
 c=categories(l)
 cb=categories(b)
 assert set(cb)=={b'RU'} and len(list(decoded(c[b'BLOCK'][1])))==44
 protected=[(k,q) for k,(_,e) in c.items() for q in decoded(e)]
 sb=list(decoded(cb[b'RU'][1]))
 for h in rules:
  hit=next((k.decode() for k,q in protected if match(h,q)),None)
  if hit or any(match(h,q) for q in sb):raise SystemExit(f'{h} already matches {hit or "Server RU"}')
 def rebuild():
  for k,(site,e) in c.items():
   if k==b'RU':
    ds={(t,n):d for f,d in e if f==2 for t,n in decoded([(f,d)])}
    for h in rules:ds[3,h]=b'\x08\x03'+s.message(2,h.encode('ascii'))
    site=s.message(1,b'RU')+b''.join(s.message(2,ds[key]) for key in sorted(ds))
   yield s.message(1,site)
 x=b''.join(rebuild())
 y,_,_=s.project(x,deny,keep)
 for old,new in ((l,x),(b,y)):
  o,n=categories(old),categories(new)
  assert set(o)==set(n)
  assert all(o[k][0]==n[k][0] for k in o if k!=b'RU')
  a0,a1=(set(decoded(d[b'RU'][1])) for d in (o,n))
  assert a0<=a1 and a1-a0=={(3,h) for h in rules}
 out=a.output
 out.mkdir(parents=True,exist_ok=True)
 for name,z in (('light',x),('server',y)):
  dest=out/(name+'-geosite_RU.dat')
  if dest.exists():raise SystemExit(f'refusing to overwrite {dest}')
  dest.write_bytes(z)
  print(name,len(s.read_ru(z)[1]),sha(z))
if __name__=='__main__':main()
