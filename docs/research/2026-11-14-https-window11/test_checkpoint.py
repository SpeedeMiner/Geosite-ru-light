from collections import Counter
import json
import unittest
from unittest.mock import patch

import checkpoint as C


class CheckpointTest(unittest.TestCase):
    def test_unique_new_urls_and_inherited_pin(self):
        plans = [C.plan(w) for w in C.WAVES]
        self.assertEqual(list(map(len, plans)), [10, 2, 6, 2, 1, 3, 8])
        urls = [r["url"] for plan in plans for r in plan]
        self.assertEqual(len(set(urls)), 32)
        self.assertEqual(len(set(r["host"] for plan in plans for r in plan)), 31)
        self.assertEqual(len(C.history()[0]), 497)

    def test_repeated_url_rejected(self):
        u = C.plan("inherited")[0]["url"]
        with patch.object(C, "history", return_value=({u}, set())):
            with self.assertRaisesRegex(ValueError, "repeated URL"):
                C.plan("inherited")

    def test_approved_delta_replays(self):
        C.assemble(C.WAVES, True)
        old = set((C.PREV / "candidate-393.txt").read_text().splitlines())
        new = set((C.HERE / "candidate-397.txt").read_text().splitlines())
        self.assertEqual(new - old, {
            "full:www.smartexpress.me", "full:medicine.minskexpo.com",
            "full:minskexpo.com", "full:www.minskexpo.com",
        })
        self.assertFalse(old - new)

    def test_catalogue_summary_and_no_contact_fields(self):
        q = json.loads((C.HERE / "14-catalogue-counts.json").read_text())
        self.assertEqual((q["power"]["rows"], q["power"]["detail_rows"],
                          q["power"]["explicit_sites"]), (285, 65, 0))
        self.assertEqual((q["kioge"]["rows"], q["kioge"]["regional_rows"]), (487, 242))
        self.assertEqual(q["electronics_pdf"]["after"], {"RU": 84, "uncovered": 6})
        self.assertEqual(q["electronics_first_page"]["after"], {"RU": 19, "no_website": 2})
        for path in C.HERE.glob("14-*.tsv"):
            self.assertNotIn("@", path.read_text())

    def test_probe_counts_and_decisions(self):
        obs = [r for p in C.HERE.glob("*-evidence-*.jsonl") for r in C.W.jsonl(p)]
        self.assertEqual(len(obs), 32)
        self.assertEqual(len({r["id"] for r in obs}), 32)
        self.assertEqual(Counter(q["asn"] for r in obs for q in r["probes"]),
                         {3216: 32, 12389: 32, 207957: 32})
        d = Counter(r["decision"] for p in C.HERE.glob("*-decisions.tsv") for r in C.W.tsv(p))
        self.assertEqual(d, {"hold_content": 16, "hold_review": 4, "hold_redirect": 5,
                             "hold_transport": 3, "accept": 4})


if __name__ == "__main__":
    unittest.main()
