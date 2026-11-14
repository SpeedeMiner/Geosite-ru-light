"""Regression tests for identity, per-probe TLS and public-content gates."""
from copy import deepcopy
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("probe_wave", Path(__file__).with_name("probe-wave.py"))
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)

class ProbeChecks(unittest.TestCase):
    def setUp(self):
        self.row = dict(host="www.example.com", url="https://www.example.com/contact?q=1",
                        brand_marker="Example Brand|Пример")
        self.now = datetime.now(timezone.utc)
        self.response = dict(id="abc", type="http", target=self.row["host"], status="finished",
                             createdAt=self.now.isoformat(), measurementOptions=dict(
                                 request=dict(method="GET", path="/contact?q=1")), results=[])
        for asn in sorted(P.ASNS):
            self.response["results"].append(dict(probe=dict(asn=asn, country="RU"), result=dict(
                status="finished", statusCode=200, rawBody="<title>Example Brand</title>" +
                "<h1>Контакты компании</h1>" * 8, tls=dict(authorized=True,
                subject=dict(alt="DNS:*.example.com, DNS:example.org")))))

    def state(self, response=None):
        return P.classify(self.row, "abc", response or self.response, self.now)["state"]

    def test_positive(self):
        self.assertEqual(self.state(), "https_candidate")

    def test_wrong_type_target_path_or_id(self):
        for field, value in {"type": "ping", "target": "example.com", "id": "def"}.items():
            with self.subTest(field=field):
                response = deepcopy(self.response)
                response[field] = value
                self.assertEqual(self.state(response), "invalid_measurement")
        self.response["measurementOptions"]["request"]["path"] = "/"
        self.assertEqual(self.state(), "invalid_measurement")

    def test_stale(self):
        self.response["createdAt"] = "2000-01-01T00:00:00.000Z"
        self.assertEqual(self.state(), "invalid_measurement")

    def test_asns_and_country(self):
        item = self.response["results"][0]["probe"]
        item["country"] = "NL"
        self.assertEqual(self.state(), "invalid_measurement")
        item["country"] = "RU"
        item["asn"] = self.response["results"][1]["probe"]["asn"]
        self.assertEqual(self.state(), "invalid_measurement")

    def test_untrusted(self):
        self.response["results"][0]["result"]["tls"]["authorized"] = False
        self.assertEqual(self.state(), "tls_or_transport_unproven")

    def test_san_depth(self):
        self.assertTrue(P.matches_san("a.example.com", ["*.example.com"]))
        for name in ("example.com", "b.a.example.com", "wrongexample.com"):
            self.assertFalse(P.matches_san(name, ["*.example.com"]))

    def test_branded_challenge(self):
        self.response["results"][0]["result"]["rawBody"] += "<p>Checking your browser</p>"
        self.assertEqual(self.state(), "content_unproven")

    def test_js_shell_only(self):
        self.response["results"][0]["result"]["rawBody"] = (
            "<title>Example Brand</title>" + "<script>data='Example Brand'</script>" * 8 + "<div id='app'></div>")
        self.assertEqual(self.state(), "content_unproven")

    def test_redirect_does_not_accept(self):
        for p in self.response["results"]:
            p["result"].update(statusCode=301, headers={"location": "/new"})
        self.assertEqual(self.state(), "redirect")

    def test_wrong_scheme(self):
        for url in ("http://www.example.com/", "https://user@www.example.com/",
                    "https://www.example.com:8080/", "https://www.example.com/#frag"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                P.url_path("www.example.com", url)

if __name__ == "__main__":
    unittest.main()
