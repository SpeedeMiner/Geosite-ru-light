#!/usr/bin/env python3
"""Verify old shard evidence and derive conservative per-host results."""
import collections, csv, hashlib, json, sys
from pathlib import Path

EXPECTED="027939e3a31591bd48a57428c893a8237fe61352d90a8c3077b39366a3a3d0cc"
RUN=45417945474
SHA="16e1afb4ba9c861c3a6f3f05aa9461f8db6c2679"

def analyze(root, out):
    root, out = Path(root), Path(out)
    out.mkdir(parents=True, exist_ok=True)
    plan=root/"vpn-fast-plan"
    manifest=json.loads((plan/"manifest.json").read_text(encoding="utf-8"))
    old=json.loads((root/"vpn-fast-coverage"/"report.json").read_text(encoding="utf-8"))
    errors=[]; hashes={}; byhost=collections.defaultdict(list)
    for p in sorted(root.rglob("*")):
        if p.is_file(): hashes[str(p.relative_to(root))]=hashlib.sha256(p.read_bytes()).hexdigest()
    if manifest.get("sha256")!=EXPECTED or old.get("sha256")!=EXPECTED: errors.append("DAT digest mismatch")
    names=manifest["hosts_to_rules"]
    if len(names)!=manifest["host_count"]: errors.append("host count mismatch")
    rules=sum(map(len,names.values()))+len(manifest["not_applicable"])
    if rules!=manifest["rule_count"]: errors.append("rule count mismatch")
    dat_path=root/"geosite_RU.dat"
    if dat_path.exists():
        from audit_ru_liveness import extract
        dat_rules=extract(dat_path.read_bytes())
        def rule_key(r): return (r["type"],r["type_code"],r["value"])
        manifest_rules=[r for rs in names.values() for r in rs]+manifest["not_applicable"]
        if collections.Counter(map(rule_key,dat_rules))!=collections.Counter(map(rule_key,manifest_rules)):
            errors.append("manifest rule multiset differs from DAT")
    planned=set(); all_shards={p.name for p in root.glob("vpn-shard-*") if p.is_dir()}
    wanted={"vpn-shard-"+str(n) for n in range(manifest["batch_count"])}
    if all_shards!=wanted: errors.append("missing/unexpected shards: "+str(sorted(all_shards^wanted)))
    seen=set(); count=0; asns=collections.Counter(); states=collections.Counter()
    for n in range(manifest["batch_count"]):
        with (plan/f"batch-{n:03}.tsv").open(encoding="utf-8",newline="") as f:
            rows=list(csv.DictReader(f,delimiter="\t"))
        batch={r["host"] for r in rows}
        if len(batch)!=len(rows) or batch & planned: errors.append(f"batch {n}: duplicate planned host")
        if not batch<=names.keys(): errors.append(f"batch {n}: host not in manifest")
        planned.update(batch)
        folder=root/f"vpn-shard-{n}"
        files=list(folder.rglob("vpnobratno-observations.jsonl"))
        summaries=list(folder.rglob("geosite-vpnobratno-summary.json"))
        if len(files)!=1: errors.append(f"batch {n}: observation files {len(files)}")
        if not summaries: errors.append(f"batch {n}: missing session summary")
        for fp in files:
            for line_no,line in enumerate(fp.read_text(encoding="utf-8").splitlines(),1):
                try: r=json.loads(line)
                except (ValueError,TypeError):
                    errors.append(f"batch {n} line {line_no}: invalid JSON"); continue
                h=r.get("host"); a=r.get("vpn_asn")
                if h not in batch: errors.append(f"batch {n}: unexpected host {h}"); continue
                if r.get("vpn_country")!="RU" or not str(a).isdigit() or int(a or 0)<=0 or r.get("asn_conflict") is not False or r.get("verified_by_sources",0)<2: errors.append(f"batch {n}: unverified exit {h}")
                if not r.get("vpn_exit_ip") or not r.get("observed_at") or not isinstance(r.get("evidence"),dict): errors.append(f"batch {n}: incomplete observation {h}")
                key=(h,str(a))
                if key in seen: errors.append(f"batch {n}: duplicate host/ASN {h}/{a}")
                seen.add(key); byhost[h].append(r); count+=1
                asns[str(a)]+=1; states[str(r.get("state"))]+=1
    if planned!=set(names): errors.append("batch union differs from manifest")
    matrix=collections.Counter(); coverage=collections.Counter(); counts=collections.Counter(); recheck=[]
    hostrows=[]; observations=[]
    for h,rules_for_host in names.items():
        obs=byhost[h]
        verified={str(o["vpn_asn"]) for o in obs if o.get("vpn_country")=="RU" and o.get("vpn_asn") and o.get("asn_conflict") is False and o.get("verified_by_sources",0)>=2}
        coverage["two_or_more_asns" if len(verified)>=2 else "one_asn" if verified else "not_tested"]+=1
        pair=tuple(sorted(str(o.get("state","unknown")) for o in obs))
        matrix[" / ".join(pair)]+=1
        available=sum(o.get("state")=="available" for o in obs)
        counts["available_both"]+=int(len(obs)==2 and available==2)
        counts["available_any"]+=int(available>0)
        counts["available_one"]+=int(available==1)
        counts["different_states"]+=int(len(set(pair))>1)
        counts["both_tls_error"]+=int(pair==("tls_error","tls_error"))
        counts["both_network_error"]+=int(pair==("network_error","network_error"))
        if len(obs)!=2 or len(verified)!=2: errors.append(f"host {h}: incomplete distinct-ASN coverage")
        if available!=2: recheck.append({"host":h,"priority":"P1","reason":"; ".join(pair)})
        hostrows.append({"hostname":h,"rules":rules_for_host,"verified_asns":sorted(verified),"states":list(pair),"observations":obs})
        for o in obs: observations.append({"host":h,"asn":o.get("vpn_asn"),"state":o.get("state"),"time":o.get("observed_at"),"ip":o.get("vpn_exit_ip"),"http":o.get("http"),"reason":(o.get("evidence") or {}).get("reason")})
    old_hosts={r["hostname"]:r for r in old["hosts"]}
    if set(old_hosts)!=set(names): errors.append("old aggregate host set mismatch")
    for h, entries in byhost.items():
        if h in old_hosts and collections.Counter(json.dumps(x,sort_keys=True,ensure_ascii=False) for x in entries)!=collections.Counter(json.dumps(x,sort_keys=True,ensure_ascii=False) for x in old_hosts[h].get("observations",[])):
            errors.append(f"old aggregate observation mismatch: {h}")
    if dict(coverage)!=old.get("coverage"): errors.append("old aggregate coverage mismatch")
    result={"source_run":RUN,"source_sha":SHA,"dat_sha256":EXPECTED,"rule_count":rules,"host_count":len(names),"shards":len(all_shards),"observations":count,"asns":dict(asns),"states":dict(states),"coverage":dict(coverage),"unique_hosts":dict(counts),"matrix":dict(matrix),"errors":errors,"file_sha256":hashes,"limitations":["exit attribution is reported by original code; independent historical network isolation not proven","network_error includes worker exceptions","available means classifier valid TLS and nonempty 2xx, not service functionality","historical redirect behavior and address family need independent inspection"]}
    (out/"integrity-report.json").write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding="utf-8")
    (out/"report.json").write_text(json.dumps({"manifest":manifest,"integrity":result,"hosts":hostrows},ensure_ascii=False,indent=2),encoding="utf-8")
    for name, fields, rows in [("coverage.csv",["hostname","verified_asns","states","rules"],hostrows),("observations.csv",["host","asn","state","time","ip","http","reason"],observations),("recheck-plan.tsv",["host","priority","reason"],recheck)]:
        with (out/name).open("w",encoding="utf-8",newline="") as f:
            w=csv.DictWriter(f,fieldnames=fields,delimiter="\t" if name.endswith(".tsv") else ",",extrasaction="ignore");w.writeheader()
            for row in rows: w.writerow({k:json.dumps(v,ensure_ascii=False) if isinstance(v,(list,dict)) else v for k,v in row.items()})
    print(json.dumps({k:v for k,v in result.items() if k!="file_sha256"},ensure_ascii=False,indent=2))
    return result

if __name__=="__main__":
    result=analyze(sys.argv[1],sys.argv[2])
    sys.exit(bool(result["errors"]))
