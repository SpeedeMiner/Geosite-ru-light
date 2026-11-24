import asyncio
import unittest
from unittest.mock import AsyncMock, patch
from ru_blocked_index import DirectPrefixIndex
from ru_blocked_web import parse_feed, matches, probe_https
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
        self.assertEqual(await self.probe(AsyncMock(return_value=(200, {}, b"<html>hello</html>"))),
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


if __name__ == "__main__":
    unittest.main()
