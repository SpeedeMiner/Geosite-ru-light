import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import verify_service_tls as tls


@unittest.skipUnless(shutil.which("openssl"), "requires OpenSSL 3")
class VerifyServiceTlsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        cls.d = Path(tmp.name)
        cls.hostname = "service.example"
        for ca in ("public", "russian", "unrelated"):
            cls.run_openssl("req", "-new", "-x509", "-nodes", "-newkey", "ec",
                            "-pkeyopt", "ec_paramgen_curve:prime256v1", "-days", "7",
                            "-subj", f"/CN={ca}", "-keyout", ca + ".key", "-out", ca + ".pem",
                            "-addext", "basicConstraints=critical,CA:true",
                            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        cls.issue("intermediate", "russian", "basicConstraints=critical,CA:true,pathlen:0\n"
                  "keyUsage=critical,keyCertSign,cRLSign\n")
        ext = ("basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\n"
               "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:service.example\n")
        cls.issue("ru-leaf", "intermediate", ext)
        cls.issue("public-leaf", "public", ext)
        cls.issue("unrelated-leaf", "unrelated", ext)
        cls.issue("cn-only", "public", ext.split("subjectAltName=")[0], "service.example")
        cls.presented("ru-chain", "ru-leaf", "intermediate")
        cls.presented("self-trust-chain", "unrelated-leaf", "unrelated")

    @classmethod
    def run_openssl(cls, *args):
        return subprocess.check_output(["openssl", *args], cwd=cls.d, stderr=subprocess.PIPE)

    @classmethod
    def issue(cls, name, issuer, ext, cn=None):
        cls.run_openssl("req", "-new", "-nodes", "-newkey", "ec",
                        "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-subj", f"/CN={cn or name}", "-keyout", name + ".key",
                        "-out", name + ".csr")
        (cls.d / (name + ".ext")).write_text(ext)
        cls.run_openssl("x509", "-req", "-in", name + ".csr", "-CA", issuer + ".pem",
                        "-CAkey", issuer + ".key", "-CAcreateserial", "-days", "2",
                        "-extfile", name + ".ext", "-out", name + ".pem")

    @classmethod
    def presented(cls, name, *parts):
        (cls.d / (name + ".pem")).write_bytes(
            b"".join((cls.d / (part + ".pem")).read_bytes() for part in parts)
        )

    def fingerprint(self, cert):
        return hashlib.sha256(self.run_openssl("x509", "-in", cert + ".pem",
                                               "-outform", "DER")).hexdigest()

    def result(self, chain, host=None, sub="intermediate", root="russian", expected=None):
        with patch.object(tls, "RU_ROOT_SHA256", self.fingerprint("russian")), \
                patch.object(tls, "RU_SUB_SHA256", self.fingerprint("intermediate")):
            return tls.audit(host or self.hostname, self.d / (chain + ".pem"),
                             self.d / (root + ".pem"), self.d / "public.pem",
                             (self.d / (sub + ".pem")) if sub else None, expected)

    def test_public_chain(self):
        result = self.result("public-leaf")
        self.assertEqual(result["verdict"], "public_store")
        self.assertTrue(result["public_store_presented"]["ok"])
        self.assertFalse(result["ru_rsa_presented"]["ok"])

    def test_russian_chain(self):
        result = self.result("ru-chain", expected=self.fingerprint("ru-leaf"))
        self.assertEqual(result["verdict"], "russian_trusted_rsa")
        self.assertFalse(result["public_store_presented"]["ok"])
        self.assertIsNone(result["ru_rsa_with_official_intermediate"])

    def test_missing_intermediate(self):
        self.assertEqual(self.result("ru-leaf", sub=None)["verdict"], "unverified")
        result = self.result("ru-leaf")
        self.assertEqual(result["verdict"], "russian_trusted_rsa_needs_intermediate")
        self.assertFalse(result["ru_rsa_presented"]["ok"])
        self.assertTrue(result["ru_rsa_with_official_intermediate"]["ok"])

    def test_wrong_hostname(self):
        result = self.result("ru-chain", host="different.example")
        self.assertEqual(result["verdict"], "unverified")
        self.assertEqual(result["ru_rsa_presented"]["error_code"], 62)

    def test_dns_san_required(self):
        self.assertEqual(self.result("cn-only")["verdict"], "missing_dns_san")

    def test_peer_cannot_supply_trust_anchor(self):
        self.assertEqual(self.result("self-trust-chain")["verdict"], "unverified")

    def test_bad_pins_rejected(self):
        with self.assertRaisesRegex(ValueError, "matching SHA-256"):
            self.result("ru-chain", root="public")
        with self.assertRaisesRegex(ValueError, "matching SHA-256"):
            self.result("ru-chain", sub="public")
        with self.assertRaisesRegex(ValueError, "observed leaf SHA-256"):
            self.result("ru-chain", expected=self.fingerprint("public-leaf"))

    def test_ip_is_not_a_hostname(self):
        with self.assertRaisesRegex(ValueError, "expected a DNS hostname"):
            self.result("ru-chain", host="192.0.2.1")


if __name__ == "__main__":
    unittest.main()
