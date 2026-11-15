import unittest

from supplement_011 import assemble_supplement, archive_order, index


def row(h, path='/', cohort='diagnostic'):
    return dict(host=h, url='https://'+h+path, cohort=cohort)


class SupplementTests(unittest.TestCase):
    def test_prioritize_only_archive_gaps_without_counting_old_root(self):
        old = [dict(host='a.test',archive_state='archive_get_root'),
               dict(host='b.test',archive_state='archive_get_other_path'),
               dict(host='c.test',archive_state='required_asn_coverage_unproven'),
               dict(host='d.test',archive_state='archive_get_other_path')]
        p = {r['host']:row(r['host'],cohort='baseline') for r in old}
        self.assertEqual([r['host'] for r in archive_order(old,p,{'d.test'})],['c.test','b.test'])
        with self.assertRaisesRegex(ValueError,'duplicate'):
            archive_order(old+old,p,set())

    def test_distinguish_another_path_from_reserved_and_live(self):
        root = row('a.test')
        current = row('a.test','/public')
        seen = row('b.test')
        front = row('c.test')
        cats = {'one':dict(frontier=[root,front],controls=[current,seen,front])}
        first, later, log = assemble_supplement(cats,{},[],{seen['url']:None},[root])
        self.assertFalse(later)
        self.assertEqual([(g,r['url']) for g,r in first],[('frontier',front['url']),('controls',current['url'])])
        self.assertEqual({x[2] for x in log},{'reserved_in_window_010','already_observed','duplicate_url'})

    def test_index_fails_on_disagreeing_rule(self):
        r = dict(row('www.test'),light_categories='RU',server_ru='yes',action='covered_control')
        idx, urls = index({'a':{'coverage':[r]},'b':{'coverage':[r]}})
        self.assertEqual(len(urls),1)
        self.assertEqual(idx[0]['catalogs'],'a|b')
        with self.assertRaisesRegex(ValueError,'disagrees'):
            index({'a':{'coverage':[r]},'b':{'coverage':[dict(r,server_ru='no')]}})
