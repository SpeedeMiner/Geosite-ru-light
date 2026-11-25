import csv, json, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import audit_raw_integrity as audit

class RawIntegrity(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)/"e"; self.out=Path(self.tmp.name)/"out"
        self.plan=self.root/"vpn-fast-plan"; self.shard=self.root/"vpn-shard-0"; self.old=self.root/"vpn-fast-coverage"
        for p in (self.plan,self.shard,self.old): p.mkdir(parents=True)
        self.rules=[{"type":"full","value":"example.org"}]
        self.manifest={"sha256":audit.EXPECTED,"hosts_to_rules":{"example.org":self.rules},"host_count":1,"rule_count":1,"not_applicable":[],"batch_count":1}
        (self.plan/"manifest.json").write_text(json.dumps(self.manifest))
        (self.plan/"batch-000.tsv").write_text("host\nexample.org\n")
        (self.shard/"geosite-vpnobratno-summary.json").write_text("{}")
        self.records=[{"host":"example.org","vpn_asn":a,"vpn_country":"RU","asn_conflict":False,"verified_by_sources":2,"vpn_exit_ip":"1.1.1.1","observed_at":"2026-01-01","evidence":{"reason":"ok"},"state":"available"} for a in (1,2)]
        self.write()
    def tearDown(self): self.tmp.cleanup()
    def write(self):
        (self.shard/"vpnobratno-observations.jsonl").write_text("".join(json.dumps(r)+"\n" for r in self.records))
        (self.old/"report.json").write_text(json.dumps({"sha256":audit.EXPECTED,"coverage":{"two_or_more_asns":1},"hosts":[{"hostname":"example.org","observations":self.records}]}))
    def runcheck(self):
        return audit.analyze(self.root,self.out)
    def test_complete(self): self.assertEqual(self.runcheck()["errors"],[])
    def test_duplicate_asn(self):
        self.records[1]["vpn_asn"]=1; self.write()
        self.assertTrue(any("duplicate" in e for e in self.runcheck()["errors"]))
    def test_unverified(self):
        self.records[0]["verified_by_sources"]=1; self.write()
        self.assertTrue(any("unverified" in e for e in self.runcheck()["errors"]))
    def test_unexpected_host(self):
        self.records[0]["host"]="other.org"; self.write()
        self.assertTrue(any("unexpected host" in e for e in self.runcheck()["errors"]))
    def test_corrupt_json(self):
        with (self.shard/"vpnobratno-observations.jsonl").open("a") as f: f.write("{bad}\n")
        self.assertTrue(any("invalid JSON" in e for e in self.runcheck()["errors"]))
    def test_missing_shard(self):
        (self.shard/"vpnobratno-observations.jsonl").unlink()
        self.assertTrue(any("observation files" in e for e in self.runcheck()["errors"]))
    def test_manifest_mismatch(self):
        self.manifest["sha256"]="bad";(self.plan/"manifest.json").write_text(json.dumps(self.manifest))
        self.assertTrue(any("digest mismatch" in e for e in self.runcheck()["errors"]))
    def test_incomplete(self):
        self.records[0]["observed_at"]="";self.write()
        self.assertTrue(any("incomplete observation" in e for e in self.runcheck()["errors"]))

if __name__=="__main__": unittest.main()
