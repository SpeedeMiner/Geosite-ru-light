import unittest
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
        self.assertRegex(audit.normalize('����  ࠧ����\n�����४⭮'),audit.PARK[0])

if __name__=='__main__': unittest.main()

