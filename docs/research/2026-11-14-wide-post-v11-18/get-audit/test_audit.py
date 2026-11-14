import unittest
from datetime import datetime,timezone
from audit import ASNS,build_request,probe_summary,same_request
from prepare import hostname

ROW=dict(host="brand.example",url="https://brand.example/contacts?a=1",markers="Good Brand")
def item(body, **changes):
    r=dict(status="finished",statusCode=200,resolvedAddress="203.0.113.10",
           rawBody=body,headers={"content-type":"text/html; charset=UTF-8"},
           tls={"authorized":True,"subject":{"alt":"DNS:*.example"}})
    r.update(changes)
    return dict(result=r,probe=dict(country="RU",asn=ASNS[0]))
def probe(body, **changes):
    return probe_summary(ROW,"get",4,item(body,**changes))
class AuditTests(unittest.TestCase):
    def test_request_modes(self):
        self.assertEqual(build_request(ROW,"get",6)["measurementOptions"],
            {"protocol":"HTTPS","ipVersion":6,"request":{"method":"GET","path":"/contacts?a=1"}})
        self.assertEqual(build_request(ROW,"dns",6)["measurementOptions"]["query"]["type"],"AAAA")
    def test_body(self):
        q=probe("<head><title>Good Brand</title></head><main>Good Brand "+("contact information. "*9)+"</main>")
        self.assertEqual(q["state"],"body_marker_observed")
    def test_title_only(self):
        q=probe("<head><title>Good Brand</title></head><body>"+("unrelated menu "*20)+"</body>")
        self.assertEqual(q["state"],"identity_unproven")
        self.assertEqual(q["title_markers"],["Good Brand"])
    def test_redirect(self):
        q=probe("",statusCode=302,headers={"Location":"https://elsewhere.example/path"})
        self.assertEqual(q["state"],"redirect_observed")
        self.assertEqual(q["redirect_host"],"elsewhere.example")
        self.assertFalse(q["redirect_followed"])
    def test_wrong_family_and_tls(self):
        self.assertEqual(probe("",resolvedAddress="2001:db8::1")["state"],"address_family_unproven")
        self.assertEqual(probe("",tls={"authorized":False})["state"],"tls_unproven")
    def test_placeholder_and_encoding(self):
        self.assertEqual(probe("<title>Just a moment</title>")["state"],"challenge_or_placeholder")
        self.assertEqual(probe("<body>\ufffd</body>")["state"],"encoding_loss")
    def test_aaaa_only(self):
        r=item("",answers=[{"type":"A","value":"192.0.2.1"},{"type":"AAAA","value":"2001:db8::1"}])
        self.assertEqual(probe_summary(ROW,"dns",6,r)["dns_answers"],["2001:db8::1"])
    def test_api_echo(self):
        at=datetime.now(timezone.utc)
        req=build_request(ROW,"get",6)
        resp=dict(id="x",type="http",target=ROW["host"],createdAt=at.isoformat(),measurementOptions=req["measurementOptions"].copy())
        self.assertTrue(same_request(resp,req,at,"x"))
        resp["measurementOptions"].pop("ipVersion")
        self.assertFalse(same_request(resp,req,at,"x"))
    def test_reject_url(self):
        for u in ["http://brand.example/","https://a@brand.example/","https://brand.example:443/","https://single/","https://brand.example/#anchor"]:
            with self.assertRaises(ValueError):hostname(u)
if __name__=="__main__":unittest.main()
