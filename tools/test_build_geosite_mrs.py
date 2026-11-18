from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from build_geosite_mrs import CHECKSUM, build, check_round_trip, rule_lines, verify_assets
from build_geosite_srs import parse_dat
from test_build_geosite_srs import FIXTURE, NAMES as SRS_NAMES


NAMES = [Path(name).with_suffix(".mrs").name for name in SRS_NAMES]


class GeoSiteMrsTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.dat = self.root / "geosite_RU.dat"
        self.dat.write_bytes(FIXTURE)
        self.categories = parse_dat(self.dat)
        self.out = self.root / "out"

    def test_rule_lines_preserve_exact_and_suffix_including_shared_base(self):
        rules = {"domain_suffix": ["example.org", "xn--p1ai"], "domain": ["example.org"]}
        self.assertEqual(list(rule_lines(rules)), ["example.org", "+.example.org", "+.xn--p1ai"])
        check_round_trip("RU", rules, "+.xn--p1ai\n+.example.org\nexample.org\n")

    def test_invalid_input_is_not_reinterpreted_by_mihomo(self):
        for host in ("+.example.com", ".example.com", "*.example.com", "x..com",
                     "x.com\ny.com", "#comment", " x.com"):
            with self.subTest(host=host), self.assertRaisesRegex(ValueError, "unrepresentable"):
                list(rule_lines({"domain": [host]}))
        with self.assertRaisesRegex(ValueError, "unsupported MRS match type"):
            list(rule_lines({"domain_regex": ["test"]}))

    def test_round_trip_rejects_missing_extra_changed_types_and_duplicates(self):
        rules = self.categories["RU"]
        exact, suffix = "allowed.example.org", "+.xn--p1ai"
        for lines, error in (
            ([exact], "1 missing"),
            ([exact, suffix, "foreign.example"], "1 unexpected"),
            (["+." + exact, suffix], "round-trip mismatch"),
            ([exact, "xn--p1ai"], "round-trip mismatch"),
            ([exact, suffix, exact], "duplicate decoded domain "),
            ([exact, suffix, suffix], "duplicate decoded domain_suffix "),
            ([exact, suffix, "# ignored by text parser"], "unrepresentable"),
        ):
            with self.subTest(lines=lines), self.assertRaisesRegex(ValueError, error):
                check_round_trip("RU", rules, "\n".join(lines))

    @staticmethod
    def fake_mihomo(cmd, *, check):
        assert check and cmd[1:3] == ["convert-ruleset", "domain"]
        mode, source, output = cmd[3:]
        if mode == "text":
            output.write_bytes(b"MRS:" + source.read_bytes())
        elif mode == "mrs":
            data = source.read_bytes()
            assert data.startswith(b"MRS:")
            output.write_bytes(b"\n".join(reversed(data[4:].splitlines())) + b"\n")
        else:
            raise AssertionError(mode)

    def build_fixture(self):
        with patch("build_geosite_mrs.subprocess.run", side_effect=self.fake_mihomo):
            build(self.categories, "mihomo", self.out)

    def test_canonical_checksum_manifest_and_file_set(self):
        self.build_fixture()
        verify_assets(self.out, NAMES)
        result = subprocess.run(["sha256sum", "--check", "--strict", CHECKSUM],
                                cwd=self.out, capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.splitlines(), [f"{name}: OK" for name in NAMES])
        self.assertEqual(self.dat.read_bytes(), FIXTURE)
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), sorted([*NAMES, CHECKSUM]))

        unexpected = self.out / "geosite_UNUSED.mrs"
        unexpected.write_bytes(b"stale")
        with self.assertRaisesRegex(ValueError, "files do not match"):
            verify_assets(self.out, NAMES)
        unexpected.unlink()
        manifest = self.out / CHECKSUM
        original = manifest.read_bytes()
        manifest.write_bytes(original + original.splitlines(keepends=True)[0])
        with self.assertRaisesRegex(ValueError, "checksum manifest"):
            verify_assets(self.out, NAMES)
        manifest.write_bytes(original)
        (self.out / NAMES[0]).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "checksum manifest"):
            verify_assets(self.out, NAMES)

    def test_late_round_trip_failure_does_not_publish_partial_results(self):
        self.build_fixture()
        old = {p.name: p.read_bytes() for p in self.out.iterdir()}

        def drop_exact(cmd, *, check):
            self.fake_mihomo(cmd, check=check)
            if cmd[3] == "mrs" and cmd[-2].name == "geosite_RU.mrs":
                cmd[-1].write_text("+.xn--p1ai\n")

        with patch("build_geosite_mrs.subprocess.run", side_effect=drop_exact):
            with self.assertRaisesRegex(ValueError, "1 missing"):
                build(self.categories, "mihomo", self.out)
            with self.assertRaisesRegex(ValueError, "1 missing"):
                build(self.categories, "mihomo", self.root / "fresh")
        self.assertEqual({p.name: p.read_bytes() for p in self.out.iterdir()}, old)
        self.assertEqual(list((self.root / "fresh").iterdir()), [])

    def test_incorrect_archive_fails_before_decompression(self):
        archive = self.root / "mihomo.gz"
        archive.write_bytes(b"untrusted archive")
        script = Path(__file__).with_name("build_geosite_mrs.sh")
        run = subprocess.run(
            ["bash", script, "--mihomo-archive", archive, "--dat", self.dat,
             "--output-dir", self.out],
            capture_output=True, text=True, check=False)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("FAILED", run.stdout)
        self.assertFalse(self.out.exists())


if __name__ == "__main__":
    unittest.main()
