import unittest
from plan_010 import assemble


def row(host,cohort='control',path='/'):
    return dict(url='https://'+host+path,host=host,cohort=cohort)


class PlanTests(unittest.TestCase):
    def test_quota_and_duplicates(self):
        a,b,c=row('a.example'),row('b.example'),row('c.example')
        first,next_,decisions=assemble([('small',[a,b]),('large',[a,c])],{b['url']},{},limit=4,reserve=1)
        self.assertEqual((first,next_),([('small',a)],[('large',c)]))
        self.assertEqual([r[-1] for r in decisions],['already_observed','duplicate_url'])

    def test_preserves_baseline_accounting_on_same_url(self):
        a,b=row('a.example'),row('a.example','baseline')
        first,next_,decisions=assemble([('n',[a]),('b',[b])],{}, {'a.example'})
        self.assertEqual((first,next_),([('b',b)],[]))
        self.assertEqual(decisions[0][-1],'baseline_replaces_diagnostic')

    def test_same_host_separate_paths_and_no_unlisted_baseline(self):
        a,b=row('a.example'),row('a.example',path='/about')
        self.assertEqual(len(assemble([('paths',[a,b])],{},set())[0]),2)
        with self.assertRaises(ValueError):
            assemble([('invalid',[row('x.example','baseline')])],{},set())


if __name__=='__main__':
    unittest.main()
