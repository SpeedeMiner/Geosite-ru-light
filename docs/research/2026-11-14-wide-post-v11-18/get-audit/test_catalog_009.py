from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest

from catalog_009 import as_plan, classify, evidence


class Catalog009Tests(unittest.TestCase):
    def setUp(self):
        self.row = dict(url='https://example.com/docs', source='https://site.example/',
                        disposition='functional', markers='Example')
        self.empty = {2:set(),3:set()}
        self.light = {'RU':self.empty,'BLOCK':self.empty}

    def test_exact_and_subdomain_are_distinct(self):
        self.light['RU'] = {2:set(),3:{'example.com'}}
        self.assertEqual(classify(self.row,self.light,self.light['RU'],{},set())['action'],'covered_control')
        www=dict(self.row,url='https://www.example.com/docs')
        self.assertEqual(classify(www,self.light,self.light['RU'],{},set())['action'],'candidate_get4')

    def test_block_and_existing_candidate_are_not_scheduled(self):
        self.light['BLOCK']={2:{'example.com'},3:set()}
        hit=classify(self.row,self.light,self.empty,{},set())
        self.assertEqual(hit['action'],'block_overlap_manual')
        self.assertEqual(hit['light_categories'],'BLOCK')
        self.light['BLOCK']=self.empty
        self.assertEqual(classify(self.row,self.light,self.empty,{}, {'full:example.com'})['action'],'candidate31_manual')
        self.assertEqual(classify(dict(self.row,disposition='third_party'),self.light,self.empty,{},set())['action'],'manual')

    def test_live_checkpoint_copy_not_counted_twice(self):
        r=dict(url=self.row['url'],id='test-id',state='observed',test='get',requested_family=4)
        with TemporaryDirectory() as root:
            p=Path(root)
            for label in ('checkpoint','final'):
                (p/f'live-{label}.jsonl').write_text(json.dumps(r)+'\n',encoding='utf-8')
            saved=evidence(p)
            self.assertEqual(len(saved),1)
            self.assertEqual(classify(self.row,self.light,self.empty,saved,set())['action'],'prior_live_get4')
            other=dict(r,id='second-id')
            (p/'live-final.jsonl').write_text(json.dumps(other)+'\n',encoding='utf-8')
            with self.assertRaises(ValueError):
                evidence(p)

    def test_plan_preserves_url_path_not_apex(self):
        inferred=classify(self.row,self.light,self.empty,{},set())
        plan=as_plan([inferred],'frontier')[0]
        self.assertEqual(plan['url'],self.row['url'])
        self.assertEqual(plan['host'],'example.com')


if __name__=='__main__':
    unittest.main()
