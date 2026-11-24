#!/usr/bin/env python3
"""Collect bounded Chrome uTLS results at the external runner."""
import asyncio,json,os
from pathlib import Path
import aiohttp
names=Path("plan603/address.txt").read_text().splitlines()
out=Path("foreign603");out.mkdir(exist_ok=True)
async def main():
 async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12),trust_env=False) as s:
  point=[]
  for u in ("https://ipapi.co/json/","https://ipinfo.io/json"):
   try:
    async with s.get(u) as r:
     d=await r.json(content_type=None);point.append({"source":u,"country":d.get("country_code") or d.get("country"),"ip":d.get("ip")})
   except Exception as e:point.append({"source":u,"error":type(e).__name__})
 sem=asyncio.Semaphore(24)
 async def one(h):
  async with sem:
   try:
    p=await asyncio.create_subprocess_exec(os.environ["AUDIT_UTLS_BIN"],h,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
    try:stdout,stderr=await asyncio.wait_for(p.communicate(),timeout=43)
    except asyncio.TimeoutError:
     p.kill();await p.communicate();return {"host":h,"error":"helper timeout"}
    if p.returncode:return {"host":h,"error":"helper exit "+str(p.returncode)}
    return json.loads(stdout)
   except Exception as e:return {"host":h,"error":type(e).__name__}
 results=await asyncio.gather(*(one(h) for h in names))
 return {"point":point,"results":results}
d=asyncio.run(main());(out/"results.json").write_text(json.dumps(d,ensure_ascii=False),encoding="utf-8")
print(json.dumps({"count":len(d["results"]),"point":d["point"]},ensure_ascii=False),flush=True)
