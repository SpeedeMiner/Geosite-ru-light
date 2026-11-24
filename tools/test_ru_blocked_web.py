import asyncio
import unittest
from unittest.mock import AsyncMock, patch
from ru_blocked_index import DirectPrefixIndex
from ru_blocked_web import parse_feed, matches, probe_https, TLSCertificateInvalid
import build_ru_blocked as builder


class WebTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.index = DirectPrefixIndex(["8.8.8.0/24"])
        self.resolve = AsyncMock(return_value=["8.8.8.8"])

    async def probe(self, fetch, threats=None):
        return await probe_https("example.com", ["8.8.8.8"], self.index,
                                 object(), threats or set(), self.resolve, fetch=fetch)

    async def test_phishing_filtered_before_network_and_parent_matches(self):
        threats = parse_feed("# feed\nhttps://scam.example/path\nmalware.example\n")
        self.assertTrue(matches("login.scam.example", threats))
        with patch.object(builder, "resolve", new=AsyncMock()) as resolve:
            result, stats = await builder.run_probes({"login.scam.example"}, self.index, {},
                False, 2, resolver=object(), threats=threats)
        self.assertEqual(result["login.scam.example"]["reason"], "phishing_or_scam")
        self.assertFalse(result["login.scam.example"]["alive"])
        resolve.assert_not_awaited()
        self.assertEqual(stats["probed"], 0)

    async def test_https_redirect_to_http_rejected(self):
        fetch = AsyncMock(return_value=(301, {"Location": "http://example.com/expired"}, b""))
        self.assertEqual(await self.probe(fetch), (False, "https_to_http_redirect"))
        self.assertEqual(fetch.await_count, 1)

    async def test_https_expired_page_rejected(self):
        body = "\u0421\u0440\u043e\u043a \u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0430\u0446\u0438\u0438 \u0434\u043e\u043c\u0435\u043d\u0430 \u0438\u0441\u0442\u0451\u043a".encode("utf-8")
        self.assertEqual(await self.probe(AsyncMock(return_value=(200, {}, body))),
                         (False, "parked_or_expired"))

    async def test_malformed_redirect_is_rejected(self):
        fetch = AsyncMock(return_value=(302, {"Location": "https://[invalid"}, b""))
        self.assertEqual(await self.probe(fetch), (False, "https_unreachable"))

    async def test_clean_https_passes(self):
        self.assertEqual(await self.probe(AsyncMock(return_value=(200, {}, b"<html><title>Welcome</title><body>Working service</body></html>"))),
                         (True, "https_ok"))

    async def test_parking_host_and_unsafe_redirect_rejected(self):
        fetch = AsyncMock(return_value=(302, {"Location": "https://parking.reg.ru/"}, b""))
        self.assertEqual(await self.probe(fetch), (False, "parked_or_expired"))
        self.assertEqual(fetch.await_count, 1)

    async def test_redirect_target_requires_direct(self):
        fetch = AsyncMock(return_value=(302, {"Location": "https://other.example/"}, b""))
        self.resolve.return_value = ["127.0.0.1", "1.1.1.1"]
        self.assertEqual(await self.probe(fetch), (False, "redirect_not_direct"))
        self.assertEqual(fetch.await_count, 1)

    async def test_unreachable_https_never_falls_back_to_http(self):
        fetch = AsyncMock(side_effect=OSError("connection refused"))
        self.assertEqual(await self.probe(fetch), (False, "https_unreachable"))
        self.assertEqual(fetch.await_count, 2)
        self.assertTrue(all(call.args[0].startswith("https://") for call in fetch.await_args_list))


    async def test_invalid_certificate_rejected(self):
        fetch = AsyncMock(side_effect=TLSCertificateInvalid("hostname parking"))
        self.assertEqual(await self.probe(fetch), (False, "tls_cert_invalid"))
        self.assertEqual(fetch.await_count, 1)

    async def test_invalid_certificate_on_redirect_rejected(self):
        fetch = AsyncMock(side_effect=[(302, {"Location": "https://other.example/"}, b""),
                                       TLSCertificateInvalid("bad certificate")])
        self.assertEqual(await self.probe(fetch), (False, "tls_cert_invalid"))

    async def test_bad_statuses_rejected(self):
        for status in (400, 403, 404, 405, 410, 451, 500):
            with self.subTest(status=status):
                self.assertEqual(await self.probe(AsyncMock(return_value=(status, {}, b"working service"))),
                                 (False, "http_status_rejected"))

    async def test_parking_in_title_or_late_body_rejected(self):
        for body in (b"<html><title>Domain is for sale</title></html>",
                     b"<html><body>" + b"x" * 32000 + b" domain expired</body></html>"):
            with self.subTest(length=len(body)):
                self.assertEqual(await self.probe(AsyncMock(return_value=(200, {}, body))),
                                 (False, "parked_or_expired"))

    async def test_empty_and_script_only_page_rejected(self):
        for body in (b"", b"<html><head><script>lotsofjavascript</script></head></html>"):
            self.assertEqual(await self.probe(AsyncMock(return_value=(200, {}, body))),
                             (False, "empty_or_trivial"))

    async def test_valid_401_or_204_passes(self):
        for status in (204, 401):
            self.assertEqual(await self.probe(AsyncMock(return_value=(status, {}, b""))),
                             (True, "https_ok"))


    async def test_hosting_placeholder_variants(self):
        for phrase in ("Сайт размещен некорректно", "Сайт размещён\n   некорректно"):
            body = ("<html><title>" + phrase + "</title></html>").encode("utf-8")
            self.assertEqual(await self.probe(AsyncMock(return_value=(200, {}, body))),
                             (False, "parked_or_expired"))

    async def test_placeholder_across_markup_and_header(self):
        body = "<html><title>Сайт <b>размещён</b> некорректно</title></html>".encode("utf-8")
        self.assertEqual(await self.probe(AsyncMock(return_value=(200, {}, body))),
                         (False, "parked_or_expired"))
        headers = {"X-Parking-Info": "Домен   не привязан"}
        self.assertEqual(await self.probe(AsyncMock(return_value=(401, headers, b""))),
                         (False, "parked_or_expired"))

    async def test_registrar_mention_alone_is_not_placeholder(self):
        body = "<html><title>Рабочий сервис</title><p>Мы пользуемся reg.ru</p></html>".encode("utf-8")
        self.assertEqual(await self.probe(AsyncMock(return_value=(200, {}, body))),
                         (True, "https_ok"))


    async def test_domain_sale_and_registrar_parking(self):
        pages = (
            "<html><title>Доменное имя agroprognoz.ru продается</title></html>",
            "<html><p>Доменное имя <b>agroprognoz.ru</b> продаётся</p></html>",
            "<html><title>Домен зарегистрирован и припаркован в Рег.ру</title></html>",
        )
        for page in pages:
            with self.subTest(page=page):
                fetch = AsyncMock(return_value=(200, {}, page.encode("utf-8")))
                self.assertEqual(await self.probe(fetch), (False, "parked_or_expired"))

    async def test_domain_sale_signature_does_not_block_unrelated_content(self):
        body = "<html><p>Прогноз погоды и сельскохозяйственные новости</p></html>".encode("utf-8")
        self.assertEqual(await self.probe(AsyncMock(return_value=(200, {}, body))),
                         (True, "https_ok"))

if __name__ == "__main__":
    unittest.main()
