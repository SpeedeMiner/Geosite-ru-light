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

func TestCrossCategoryCoverageIsNotRUApproval(t *testing.T) {
    empty:=func()rules{return rules{roots:map[string]bool{},full:map[string]bool{},opaque:map[string]bool{}}}
    yt:=empty();yt.roots["youtube.com"]=true;yt.roots["ytimg.com"]=true
    tg:=empty();tg.roots["telegram.org"]=true
    one:=empty();one.full["exact.example.net"]=true
    categories:=map[string]rules{
        "RU":empty(),"BLOCK":empty(),"YOUTUBE":yt,"TELEGRAM":tg,"CUSTOM":one,
    }
    rows:=[]discoveredDomainRow{
        {Domain:"www.youtube.com",Signals:"CSP"},
        {Domain:"s.ytimg.com",Signals:"CSP"},
        {Domain:"telegram.org",Signals:"CSP"},
        {Domain:"exact.example.net",Signals:"CSP"},
        {Domain:"sub.exact.example.net",Signals:"CSP"},
        {Domain:"thirdparty.example.io",Signals:"CSP"},
    }
    matches,n:=otherCompiledCategoryMatches(rows,categories)
    if n!=4{t.Fatalf("expected 4 other-category matches, got %d",n)}
    for _,tc:=range []struct{domain,cat string}{
        {"www.youtube.com","YOUTUBE"},{"s.ytimg.com","YOUTUBE"},
        {"telegram.org","TELEGRAM"},{"exact.example.net","CUSTOM"},
    } {
        if len(matches[tc.domain])!=1 || matches[tc.domain][0]!=tc.cat {
            t.Fatalf("incorrect compiled DAT overlap for %s: %v",tc.domain,matches[tc.domain])
        }
    }
    for _,domain:=range []string{"sub.exact.example.net","thirdparty.example.io"} {
        if len(matches[domain])!=0{t.Fatalf("unexpected Full or absent coverage for %s: %v",domain,matches[domain])}
    }
    path:=filepath.Join(t.TempDir(),"review_queue.tsv")
    if err:=writeDiscoveryReviewQueue(path,nil,rows,matches);err!=nil{t.Fatal(err)}
    data,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
    output:=string(data)
    for _,frag:=range []string{
        "domain\treview_priority\tother_dat_categories",
        "www.youtube.com\tWEAK_FOREIGN_DEPENDENCY\tYOUTUBE",
        "thirdparty.example.io\tWEAK_FOREIGN_DEPENDENCY",
        "UNREVIEWED\tNO",
    } {
        if !strings.Contains(output,frag){t.Fatalf("review queue missing %q",frag)}
    }
    if strings.Contains(output,"AUTO_APPROVED") || strings.Contains(output,"domain:youtube.com") {
        t.Fatal("audit queue must not promote or widen rules")
    }
}
