package main

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestFilterDiscoveryNeverOverridesExistingPolicy(t *testing.T) {
    ru:=rules{roots:map[string]bool{"example.ru":true},full:map[string]bool{"only.example.net":true},opaque:map[string]bool{}}
    block:=rules{roots:map[string]bool{"track.example.org":true},full:map[string]bool{},opaque:map[string]bool{}}
    reviews:=map[string]reviewDecision{
        "foreign.example.com":{status:"reject",rationale:"foreign"},
        "uncertain.example.net":{status:"hold",rationale:"missing owner proof"},
    }
    names:=[]string{"img.example.ru","only.example.net","sub.track.example.org",
        "foreign.example.com","uncertain.example.net","media.4pda.to",
        "new.example.com","new.example.org","foreign-external.example.io"}
    var input []discoveredDomainRow
    for _,n:=range names{
        r:=discoveredDomainRow{Domain:n,Signals:"CSP",Seeds:"seed.ru"}
        if n=="new.example.com"{r.Signals="TLS_SAN"}
        if n=="new.example.org"{r.Seeds="seed.ru; partner.ru"}
        input=append(input,r)
    }
    out,weak,counts:=filterDiscoveryCandidates(input,ru,block,reviews)
    if len(out)!=2||out[0].Domain!="new.example.com"||out[1].Domain!="new.example.org" {
        t.Fatalf("unexpected actionable domain list: %+v",out)
    }
    if len(weak)!=1||weak[0].Domain!="foreign-external.example.io"{
        t.Fatalf("third-party single CSP with no CORE should be weak evidence: %+v",weak)
    }
    for k,expected:=range map[string]int{"observed":9,"covered_RU":2,"covered_BLOCK":1,
        "review_reject":1,"review_hold":1,"4pda_excluded":1,"new":3,
        "priority_review":2,"weak_external_dependencies":1} {
        if counts[k]!=expected{t.Errorf("%s: got %d expected %d",k,counts[k],expected)}
    }
}

func TestReadDiscoveryTSVValidatesHeaderAndDomains(t *testing.T) {
    path:=filepath.Join(t.TempDir(),"raw.tsv")
    header:="domain\tsignals\tseeds\tevidence\tpublic_dns_ips\tmatched_core_asns\tmatched_core_groups\tdns_checked\n"
    row:="new.example.net\tTLS_SAN\tseed.example.ru\tTLS SAN of seed.example.ru\t8.8.8.8\tAS100\tTestGroup\tyes\n"
    if err:=os.WriteFile(path,[]byte(header+row),0600);err!=nil{t.Fatal(err)}
    parsed,err:=readDiscoveryTSV(path)
    if err!=nil||len(parsed)!=1||parsed[0].Domain!="new.example.net"{
        t.Fatalf("expected one normalized domain: %v %+v",err,parsed)
    }
    if err:=os.WriteFile(path,[]byte(header+row+row),0600);err!=nil{t.Fatal(err)}
    if _,err:=readDiscoveryTSV(path);err==nil{t.Fatal("duplicate domain must fail")}
    if err:=os.WriteFile(path,[]byte(header+strings.Replace(row,"new.example.net","../../etc/passwd",1)),0600);err!=nil{t.Fatal(err)}
    if _,err:=readDiscoveryTSV(path);err==nil{t.Fatal("unsafe domain must fail")}
}
