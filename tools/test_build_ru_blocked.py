import asyncio
import ipaddress
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, patch

import build_ru_blocked as b
from ru_blocked_index import DirectPrefixIndex


class CodecTest(unittest.TestCase):
    def test_dat_preserves_rule_types(self):
        expected = {(2, "example.com"), (3, "host.example.com")}
        self.assertEqual(b.extract_rules(b.encode_dat(expected))[0], expected)

    def test_geoip_cidr(self):
        cidr = b.blob(1, ipaddress.ip_address("8.8.8.0").packed) + b.encvar(16) + b.encvar(24)
        dat = b.blob(1, b.blob(1, b"RU") + b.blob(2, cidr))
        self.assertEqual(b.extract_cidrs(dat), ["8.8.8.0/24"])

    def test_invalid_payload(self):
        with self.assertRaises(ValueError):
            b.extract_rules(b"\x0a\x10\x01")

    def test_cache_ttl(self):
        now = 1000000
        row = dict(ips=["8.8.8.8"], in_direct_geoip=True, alive=True, checked_at=now-6*86400, fail_streak=0, probe_version=b.PROBE_VERSION)
        self.assertTrue(b.cache_fresh(row, now))
        row["checked_at"] = now-8*86400
        self.assertFalse(b.cache_fresh(row, now))
        row.update(alive=False, checked_at=now-2*86400, fail_streak=1)
        self.assertFalse(b.cache_fresh(row, now))
        row["fail_streak"] = 3
        self.assertTrue(b.cache_fresh(row, now))

    def test_cache_rechecks_changed_direct_index(self):
        index = DirectPrefixIndex(["1.1.1.0/24"])
        cache = {"example.com": dict(ips=["8.8.8.8"], in_direct_geoip=True,
                                      alive=True, checked_at=time.time(), fail_streak=0, probe_version=b.PROBE_VERSION)}
        with patch.object(b, "resolve", new=AsyncMock(return_value=["1.1.1.1"])), \
             patch.object(b, "probe_https", new=AsyncMock(return_value=(True, "https_ok"))):
            result, stats = asyncio.run(b.run_probes(set(cache), index, cache, False, 2, resolver=object()))
        self.assertEqual(stats["probed"], 1)
        self.assertTrue(result["example.com"]["alive"])
        self.assertEqual(result["example.com"]["ips"], ["1.1.1.1"])


    def test_old_cache_is_invalidated(self):
        now = time.time()
        row = dict(ips=["8.8.8.8"], direct_ips=["8.8.8.8"], in_direct_geoip=True,
                   alive=True, checked_at=now, fail_streak=0)
        self.assertFalse(b.cache_fresh(row, now))

    def test_no_https_reason_in_probe_cache(self):
        index = DirectPrefixIndex(["1.1.1.0/24"])
        with patch.object(b, "resolve", new=AsyncMock(return_value=["1.1.1.1"])), \
             patch.object(b, "probe_https", new=AsyncMock(return_value=(False, "https_unreachable"))):
            result, _ = asyncio.run(b.run_probes({"example.com"}, index, {}, False, 2, resolver=object()))
        self.assertFalse(result["example.com"]["alive"])
        self.assertEqual(result["example.com"]["reason"], "https_unreachable")
        self.assertEqual(result["example.com"]["probe_version"], b.PROBE_VERSION)

if __name__ == "__main__":
    unittest.main()

