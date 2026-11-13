from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from fetch_geosite_sources import CACHE_TTL, Source, digest, fetch


class FetchTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.cache = self.root / "cache"
        self.source = Source("community", "https://example.org/inputs.dat",
                             self.root / "source.dat", 2)
        self.now = 10 * CACHE_TTL

    def seed(self, source=None):
        source = source or self.source
        state, checksum, when, _ = fetch(source, self.cache, self.now, self.fresh)
        self.assertEqual(("fresh", digest(source.output), self.now),
                         (state, checksum, when))
        return checksum

    @staticmethod
    def fresh(url, path):
        path.write_bytes(b"known good\n")

    @staticmethod
    def failed(url, path):
        path.write_bytes(b"partial")
        raise OSError("upstream unavailable")

    def test_fallback_preserves_origin_hash_and_age(self):
        checksum = self.seed()
        state, sha, when, _ = fetch(self.source, self.cache, self.now + 60, self.failed)
        self.assertEqual(("fallback", checksum, self.now), (state, sha, when))
        self.assertEqual(b"known good\n", self.source.output.read_bytes())

    def test_empty_live_response_uses_snapshot(self):
        self.seed()
        state, _, _, _ = fetch(self.source, self.cache, self.now + 1,
                               lambda url, path: path.touch())
        self.assertEqual("fallback", state)

    def test_changed_url_is_not_reused(self):
        self.seed()
        changed = Source(self.source.name, "https://example.org/new.dat",
                         self.source.output, 2)
        self.assertEqual("failed", fetch(changed, self.cache, self.now, self.failed)[0])
        self.assertFalse(changed.output.exists())

    def test_expired_or_future_snapshot_is_not_reused(self):
        self.seed()
        for now in (self.now + CACHE_TTL + 1, self.now - 1):
            self.assertEqual("failed", fetch(self.source, self.cache, now, self.failed)[0])
            self.assertFalse(self.source.output.exists())

    def test_corrupt_snapshot_is_not_reused(self):
        self.seed()
        (self.cache / self.source.name / "payload").write_bytes(b"changed")
        self.assertEqual("failed", fetch(self.source, self.cache, self.now, self.failed)[0])
        self.assertFalse(self.source.output.exists())

    def test_cache_write_failure_does_not_discard_live_input(self):
        self.cache.touch()
        state, checksum, _, warning = fetch(self.source, self.cache, self.now, self.fresh)
        self.assertEqual("fresh", state)
        self.assertEqual(digest(self.source.output), checksum)
        self.assertIn("could not stage snapshot", warning)

    def test_cold_cache_fails_without_writing_partial_input(self):
        self.assertEqual("failed", fetch(self.source, self.cache, self.now, self.failed)[0])
        self.assertFalse(self.source.output.exists())

    def test_tier1_does_not_use_snapshot(self):
        self.seed()
        critical = Source(self.source.name, self.source.url, self.source.output, 1)
        self.assertEqual("failed", fetch(critical, self.cache, self.now, self.failed)[0])
        self.assertFalse(critical.output.exists())

    def test_runet_requires_matching_published_checksum(self):
        source = Source("runetfreedom", self.source.url, self.source.output, 1)
        digest_url = "https://example.org/inputs.dat.sha256sum"

        def upstream(url, path):
            if url == digest_url:
                path.write_text("0" * 64 + "  geosite.dat\n")
            else:
                self.fresh(url, path)

        with patch("fetch_geosite_sources.time.sleep") as sleep:
            self.assertEqual("failed", fetch(source, self.cache, self.now,
                                             upstream, digest_url)[0])
            self.assertEqual(2, sleep.call_count)
        self.assertFalse(source.output.exists())

        def verified(url, path):
            if url == digest_url:
                from hashlib import sha256
                path.write_text(sha256(b"known good\n").hexdigest() + "  geosite.dat\n")
            else:
                self.fresh(url, path)

        self.assertEqual("fresh", fetch(source, self.cache, self.now,
                                        verified, digest_url)[0])
        self.assertFalse((self.cache / "runetfreedom").exists())


if __name__ == "__main__":
    unittest.main()
