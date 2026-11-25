#!/usr/bin/env python3
"""Find exact priority names in SHA-verified locked source inputs."""
import asyncio,csv,hashlib,json,re
from pathlib import Path
import aiohttp
from audit_ru_liveness import fields
names=[r["hostname"] for r in csv.DictReader(Path("existing/removal-review.csv").open(encoding="utf-8",newline=""))]
lock=json.loads(Path("data/geosite-inputs.lock.json").read_text())
def dat_matches(data):
    matches={n:[] for n in names}
    for f,w,site in fields(data):
        if (f,w)!=(1,2): continue
        fs=list(fields(site)); category=next((v.decode("utf-8","replace") for n,t,v in fs if (n,t)==(1,2)),"")
        for n,t,v in fs:
            if (n,t)!=(2,2):continue
            x=list(fields(v)); value=next((q.decode("utf-8","replace").lower() for a,b,q in x if (a,b)==(2,2)),"")
            typ=next((q for a,b,q in x if (a,b)==(1,0)),0)
            if value in matches:matches[value].append({"category":category,"type_code":typ})
    return {k:v for k,v in matches.items() if v}
async def main():
 async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=100),trust_env=False) as session:
  async def get(row):
    try:
      async with session.get(row["url"]) as r:
        r.raise_for_status();data=await r.read()
      h=hashlib.sha256(data).hexdigest()
      if h!=row["sha256"] or len(data)!=row["size"]:return {"source":row["name"],"status":"digest_mismatch"}
      if row["output"].endswith(".dat"):
        matches=dat_matches(data)
      else:
        matches={}
        for n,line in enumerate(data.decode("utf-8","replace").splitlines(),1):
          for host in names:
            if re.search(r"(?<![a-z0-9-])"+re.escape(host)+r"(?![a-z0-9-])",line,re.I):
              matches.setdefault(host,[]).append({"line":n,"text":line[:300]})
      return {"source":row["name"],"status":"verified","sha256":h,"matches":matches}
    except Exception as e:return {"source":row["name"],"status":"error","error":type(e).__name__}
  sem=asyncio.Semaphore(4)
  async def limited(row):
   async with sem:return await get(row)
  return await asyncio.gather(*(limited(row) for row in lock["sources"]))
results=asyncio.run(main())
out=Path("source-audit");out.mkdir(exist_ok=True)
(out/"locked-source-matches.json").write_text(json.dumps({"sources":results,"limitations":["presence in a locked source category does not prove that the category was selected or responsible for inclusion","locked snapshot may not match the inputs of the historical rolling release"]},ensure_ascii=False,indent=2),encoding="utf-8")
print(json.dumps(results,ensure_ascii=False),flush=True)
