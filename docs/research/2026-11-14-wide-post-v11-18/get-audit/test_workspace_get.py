import unittest
from workspace_get import check_url,result,safe_location

class WorkspaceGetTests(unittest.TestCase):
    row = dict(host='example.com',url='https://example.com/about',markers='Example')
    def test_returns_no_ru_credit_even_with_marker(self):
        s=result(self.row,0,dict(response_code=200,http_connect=200,content_type='text/html',ssl_verify_result=0),
                 b'<title>Example</title><main>Example</main>')
        self.assertEqual(s['state'],'workspace_marker')
        self.assertTrue(s['proxy_connect'])
        self.assertFalse(s['fresh_ru_credit'])
        self.assertNotIn('asn',s)
    def test_redirect_omits_sensitive_parts(self):
        self.assertEqual(safe_location(self.row['url'],'https://a:b@test.example/path?token=1#foo'),('test.example','https://test.example/path'))
    def test_no_inferred_reachability_from_partial_timeout(self):
        self.assertEqual(result(self.row,28,dict(response_code=200),b'')['state'],'workspace_transport_unproven')
    def test_exact_https_without_control_characters(self):
        self.assertEqual(check_url(self.row['url']),'example.com')
        for x in ('http://example.com/','https://example.com:443/','https://example.com//unsafe',
                  'https://example.com/foo\rbar'):
            with self.assertRaises(ValueError):
                check_url(x)
