import unittest
from next_queue_012 import ordered_batches
from plan_010 import assemble

def row(host, cohort='diagnostic', path='/'):
    return dict(host=host,url='https://'+host+path,cohort=cohort)

class NextQueueTests(unittest.TestCase):
    def test_existing_priorities_remain_ahead_of_new_data(self):
        a,b,c=row('a.example'),row('b.example'),row('c.example')
        batches=ordered_batches([('existing',[a])],{'sector':{'frontier':[b],'controls':[a,c]}})
        first, later, log=assemble(batches,{},set(),limit=6,reserve=0)
        self.assertEqual([r for _,r in first],[a,b])
        self.assertEqual([r for _,r in later],[c])
        self.assertEqual(log,[('new_controls_sector',a['url'],'duplicate_url')])
