import json, time, urllib.request, urllib.error
from pathlib import Path
base='https://api.globalping.io/v1/measurements'
headers={'Content-Type':'application/json','User-Agent':'GeositeRuLight-Audit/1.0'}
def create(host,location=None):
    payload={'type':'http','target':host,'limit':1,'measurementOptions':{'ipVersion':6,'protocol':'HTTPS','request':{'method':'GET','path':'/'}}}
    if location:payload['locations']=location
    try:
        with urllib.request.urlopen(urllib.request.Request(base,data=json.dumps(payload).encode(),headers=headers,method='POST'),timeout=15) as r:return json.load(r)
    except urllib.error.HTTPError as e:return {'error':str(e),'body':e.read(4000).decode('utf8','replace')}
    except Exception as e:return {'error':str(e)}
def get(mid):
    try:
        with urllib.request.urlopen(urllib.request.Request(base+'/'+mid,headers=headers),timeout=15) as r:return json.load(r)
    except Exception as e:return {'error':str(e)}
control=create('one.one.one.one'); result={'control_creation':control,'measurements':{}}
if 'id' in control:
    for i in range(25):
        time.sleep(2); status=get(control['id'])
        if status.get('status')!='in-progress':break
    result['control']=status
    # The service reports resolvedAddress and an HTTP status from the same probe; retain raw evidence.
    text=json.dumps(status).lower()
    if status.get('status')=='finished' and ('2606:4700' in text) and ('http/' in text or 'statuscode' in text):
        for h in [x.strip() for x in open('previous/UNKNOWN.txt') if any(t in x for t in ('ipv6','ip6','6.ipquail','6.wsmdn','v6.'))]:
            result['measurements'][h]=create(h,control['id']);time.sleep(.25)
        time.sleep(35)
        for h,v in result['measurements'].items():
            if 'id' in v:result['measurements'][h]={'created':v,'result':get(v['id'])}
    else: result['skipped']='IPv6 control did not prove HTTP response on native IPv6'
Path('globalping-ipv6.json').write_text(json.dumps(result,indent=2))

