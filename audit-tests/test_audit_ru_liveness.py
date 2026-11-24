import unittest
import sys
import asyncio
from unittest.mock import patch
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from publicsuffix2 import PublicSuffixList
import audit_ru_liveness as audit

def v(n):
    return bytes([n])

def field(n, data):
    return v(n*8+2)+v(len(data))+data

class AuditTests(unittest.TestCase):
    def test_extract_and_preserve_types(self):
        domain=bytes([8,2])+field(2,b'example.com')
        full=bytes([8,3])+field(2,b'api.example.com')
        dat=field(1,field(1,b'RU')+field(2,domain)+field(2,full))
        result=audit.extract(dat)
        self.assertEqual([(r['type'],r['value']) for r in result],[('domain','example.com'),('full','api.example.com')])

    def test_missing_category_fails(self):
        with self.assertRaises(ValueError): audit.extract(field(1,field(1,b'US')))

    def test_suffix_and_uncheckable(self):
        psl=PublicSuffixList()
        self.assertFalse(audit.applicable({'type':'domain','value':'ru'},psl)[0])
        self.assertFalse(audit.applicable({'type':'regex','value':'.*example'},psl)[0])
        self.assertTrue(audit.applicable({'type':'domain','value':'example.com'},psl)[0])

    def test_public_address(self):
        self.assertFalse(audit.public('127.0.0.1'))
        self.assertFalse(audit.public('169.254.169.254'))
        self.assertTrue(audit.public('8.8.8.8'))

    def test_placeholder_normalization(self):
        self.assertRegex(audit.normalize('Сайт  размещён\nнекорректно'),audit.PARK[0])

    def test_dns_a_and_aaaa_are_queried_concurrently(self):
        async def check():
            entered=[]; ready=asyncio.Event()
            class Answer:
                rrset=True
                def __init__(self, kind): self.kind=kind
                def __iter__(self): return iter(['8.8.8.8' if self.kind=='A' else '2001:4860:4860::8888'])
            async def fake(name,kind,**kwargs):
                entered.append(kind)
                if len(entered)==2: ready.set()
                await asyncio.wait_for(ready.wait(),1)
                return Answer(kind)
            with patch.object(audit.dns.asyncresolver,'resolve',side_effect=fake):
                result=await audit.resolve('parallel.example',fresh=True)
            self.assertCountEqual(entered,['A','AAAA'])
            self.assertEqual(result['A']['status'],'ok')
            self.assertEqual(result['AAAA']['status'],'ok')
        asyncio.run(check())

if __name__=='__main__': unittest.main()
