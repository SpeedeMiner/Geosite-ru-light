import csv
import importlib.util
import unittest
from unittest.mock import patch

import checkpoint as C


def load_file(name):
    spec = importlib.util.spec_from_file_location(name, C.HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CheckpointTest(unittest.TestCase):
    def test_wave_pins_and_unambiguous_urls(self):
        waves = [C.plan(w) for w in C.WAVES]
        self.assertEqual(list(map(len, waves)), [6, 6, 6, 7, 5, 8, 3])
        rows = [r for wave in waves for r in wave]
        self.assertEqual(len({r["url"] for r in rows}), len(rows))
        self.assertEqual(len({r["host"] for r in rows}), 31)

    def test_known_url_without_receipt_cannot_be_reused(self):
        row = C.plan("inherited")[0]
        with patch.object(C, "history", return_value=({row["url"]}, set())):
            with self.assertRaisesRegex(ValueError, "repeated URL"):
                C.plan("inherited")

    def test_replay_and_exact_delta(self):
        C.assemble(C.WAVES, True)
        old = set((C.PREV / "candidate-385.txt").read_text().splitlines())
        new = set((C.HERE / "candidate-390.txt").read_text().splitlines())
        self.assertFalse(old - new)
        self.assertEqual(new - old, {"full:" + h for h in (
            "ea-cmcb.com", "www.ea-cmcb.com", "www.globalports.com",
            "www.lekpharm.com", "lekpharm.com")})

    def test_receipts_are_compact(self):
        ids = []
        for f in C.HERE.glob("*-evidence-*.jsonl"):
            for record in C.W.jsonl(f):
                ids.append(record["id"])
                self.assertEqual({q["asn"] for q in record["probes"]}, {3216, 12389, 207957})
                for probe in record["probes"]:
                    self.assertTrue({"rawBody", "rawOutput", "og"}.isdisjoint(probe))
        self.assertEqual(len(set(ids)), len(ids))
        self.assertEqual(len(ids), 41)

    def test_catalogue_extractor_country_only_and_text_hint(self):
        e = load_file("extract-catalogue")
        html = """<td class="exhib-td"><h2 class='exhib-name'>
        <a href='https://kihe.kz/details?a=1&amp;b=2'>Example Ltd</a></h2>
        <div class='exhib-city'><i></i> Казахстан</div>
        <p class='bg_t_onsite'>Contacts www.example.org. me@www.invalid.test</p></td>"""
        self.assertEqual(e.extract(html, "kihe.kz"),
                         [("Казахстан", "Example Ltd", "https://kihe.kz/details?a=1&b=2", "www.example.org")])
        with self.assertRaises(ValueError):
            e.extract(html, "unrelated.example")

    def test_prodexpo_cards_and_duplicate_guard(self):
        e = load_file("extract-prodexpo")
        link = "https://icatalog.expocentr.ru" + e.EXPO + "123?stand=A1"
        html = f'''<html><a data-stand="A1" href="{link}"><div><h4 class="list-group-item-heading">Alpha &amp; Co</h4></div></a></html>'''
        self.assertEqual(e.extract([html]), [(1, "A1", "Alpha & Co", link)])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            e.extract([html, html])
        with self.assertRaisesRegex(ValueError, "incomplete"):
            e.extract([html[:-7]])

    def test_website_field_excludes_mail_and_organizer_navigation(self):
        e = load_file("extract-prodexpo-websites")
        html = ('<a href="https://organizer.example/">Navigation</a>'
                '<dt>E-mail:</dt><dd><a href="mailto:shop@example.org">Mail</a></dd>'
                '<dt>Сайт: </dt><dd><a href="http://www.example.org">Company</a>'
                '<a href="https://user:password@example.org">Invalid</a></dd>')
        self.assertEqual(e.websites(html), ["http://www.example.org"])


if __name__ == "__main__":
    unittest.main()
