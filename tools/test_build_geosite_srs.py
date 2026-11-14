import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from build_geosite_srs import CHECKSUM, build, parse_dat, verify_assets


def varint(value):
    out = bytearray()
    while value > 127:
        out.append((value & 127) | 128)
        value >>= 7
    return bytes(out) + bytes([value])


def message(field, value):
    return varint(field * 8 + 2) + varint(len(value)) + value


def site(name, entries):
    result = message(1, name.encode())
    for kind, host, extra in entries:
        result += message(2, b"\x08" + varint(kind) + message(2, host.encode()) + extra)
    return message(1, result)


FIXTURE = (
    site("RU", [(2, "xn--p1ai", b""), (3, "allowed.example.org", b"")])
    + site("BLOCK", [(2, "example.net", b"")])
    + site("GOOGLE-PLAY", [(2, "play.example.com", b"")])
)
NAMES = ["geosite_BLOCK.srs", "geosite_GOOGLE-PLAY.srs", "geosite_RU.srs"]


class GeoSiteSrsTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.dat = self.root / "test.dat"
        self.dat.write_bytes(FIXTURE)
        self.out = self.root / "out"

    def test_parse_preserves_exact_and_suffix_types_in_separate_categories(self):
        self.assertEqual(parse_dat(self.dat), {
            "RU": {"domain": ["allowed.example.org"], "domain_suffix": ["xn--p1ai"]},
            "BLOCK": {"domain_suffix": ["example.net"]},
            "GOOGLE-PLAY": {"domain_suffix": ["play.example.com"]},
        })

    def test_reject_unrepresentable_or_unsafe_dat(self):
        for invalid in (
            FIXTURE[:-1],
            FIXTURE + site("../RU", [(2, "example.org", b"")]),
            FIXTURE + site("RU", [(2, "example.org", b"")]),
            FIXTURE + site("OTHER", [(0, "example.org", b"")]),
            FIXTURE + site("OTHER", [(1, "example.org", b"")]),
            FIXTURE + site("OTHER", [(3, "example.org", message(3, b"attribute"))]),
            FIXTURE + site("OTHER", []),
            site("BLOCK", [(2, "example.org", b"")]),
        ):
            with self.subTest(invalid=invalid):
                self.dat.write_bytes(invalid)
                with self.assertRaises(ValueError):
                    parse_dat(self.dat)

    @staticmethod
    def fake_compiler(cmd, check):
        source, output = cmd[-1], cmd[-2]
        data = json.loads(source.read_text())
        if cmd[2] == "decompile":
            data["rules"][0] = {key: value[0] if len(value) == 1 else value[::-1]
                                for key, value in data["rules"][0].items()}
        output.write_text(json.dumps(data))

    def test_roundtrip_checksum_and_unexpected_assets(self):
        with patch("build_geosite_srs.subprocess.run", side_effect=self.fake_compiler):
            build(parse_dat(self.dat), "sing-box", self.out)
        verify_assets(self.out, NAMES)
        (self.out / "geosite_UNUSED.srs").write_bytes(b"unexpected")
        with self.assertRaisesRegex(ValueError, "files do not match"):
            verify_assets(self.out, NAMES)
        (self.out / "geosite_UNUSED.srs").unlink()
        (self.out / "geosite_BLOCK.srs").write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "checksum manifest"):
            verify_assets(self.out, NAMES)

    def test_exact_to_suffix_widening_blocks_all_output(self):
        def widen(cmd, check):
            self.fake_compiler(cmd, check)
            if cmd[2] == "decompile" and cmd[-1].name == "geosite_RU.srs":
                target = cmd[-2]
                data = json.loads(target.read_text())
                rule = data["rules"][0]
                rule["domain_suffix"] = [rule["domain_suffix"], rule.pop("domain")]
                target.write_text(json.dumps(data))

        with patch("build_geosite_srs.subprocess.run", side_effect=widen):
            with self.assertRaisesRegex(ValueError, "changed match types"):
                build(parse_dat(self.dat), "sing-box", self.out)
        self.assertFalse((self.out / CHECKSUM).exists())
        self.assertEqual(list(self.out.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
