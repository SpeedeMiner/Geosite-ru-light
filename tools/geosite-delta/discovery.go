package main

// Evidence-only corporate discovery filter. It does not modify the protobuf
// GeoSite data or authorize inclusion in RU-DIRECT.
import (
    "encoding/csv"
    "fmt"
    "os"
    "regexp"
    "sort"
    "strings"
)

var discoveryDomainRE = regexp.MustCompile("^[a-z0-9-]+(?:\\.[a-z0-9-]+)+$")

type discoveredDomainRow struct {
    Domain string
    Signals string
    Seeds string
    Evidence string
    IPs string
    ASNs string
    Groups string
    DNSChecked string
}

func readDiscoveryTSV(path string) ([]discoveredDomainRow,error) {
    f,err:=os.Open(path);if err!=nil{return nil,err};defer f.Close()
    reader:=csv.NewReader(f);reader.Comma='\t';reader.FieldsPerRecord=8
    all,err:=reader.ReadAll();if err!=nil{return nil,err}
    expected:=[]string{"domain","signals","seeds","evidence","public_dns_ips","matched_core_asns","matched_core_groups","dns_checked"}
    if len(all)==0{return nil,fmt.Errorf("missing discovery header")}
    for i,name:=range expected{if all[0][i]!=name{return nil,fmt.Errorf("discovery header %d: got %q expected %q",i,all[0][i],name)}}
    var result []discoveredDomainRow
    seen:=map[string]bool{}
    for n,parts:=range all[1:]{
        domain:=strings.ToLower(strings.TrimSpace(parts[0]))
        if !discoveryDomainRE.MatchString(domain)||len(domain)>253||strings.HasPrefix(domain,"-") {
            return nil,fmt.Errorf("invalid discovery domain row %d: %q",n+2,domain)
        }
        if seen[domain]{return nil,fmt.Errorf("duplicate discovery domain: %s",domain)}
        if parts[7]!="yes"&&parts[7]!="no"{return nil,fmt.Errorf("invalid DNS status for %s",domain)}
        seen[domain]=true
        result=append(result,discoveredDomainRow{domain,parts[1],parts[2],parts[3],parts[4],parts[5],parts[6],parts[7]})
    }
    return result,nil
}

func safeMarkdown(s string) string {
    s=strings.ReplaceAll(s,"|","/")
    s=strings.ReplaceAll(s,"\n"," ")
    s=strings.ReplaceAll(s,"\r"," ")
    s=strings.ReplaceAll(s,string(rune(96)),"'")
    if len(s)>240{s=s[:240]+"…"}
    return s
}

func excluded4PDASubtree(name string) bool {
    return name=="4pda.to"||strings.HasSuffix(name,".4pda.to")
}

// filterDiscoveryCandidates compares actual protobuf RootDomain/Full coverage.
// The prior human review is independent evidence: neither an ASN match nor a
// TLS SAN/first-party CSP is sufficient to override a hold/reject.
func filterDiscoveryCandidates(rows []discoveredDomainRow, ru, block rules, reviews map[string]reviewDecision) (
    actionable []discoveredDomainRow, counts map[string]int) {
    counts=map[string]int{"observed":0,"covered_RU":0,"covered_BLOCK":0,
        "review_hold":0,"review_reject":0,"4pda_excluded":0,"new":0}
    for _,row:=range rows{
        counts["observed"]++
        if excluded4PDASubtree(row.Domain) {
            counts["4pda_excluded"]++
            continue
        }
        if covered(ru,row.Domain,false) {
            counts["covered_RU"]++
            continue
        }
        if covered(block,row.Domain,false) {
            counts["covered_BLOCK"]++
            continue
        }
        if review,ok:=reviews[row.Domain];ok {
            switch review.status {
            case "reject":counts["review_reject"]++;continue
            case "hold":counts["review_hold"]++;continue
            }
        }
        counts["new"]++
        actionable=append(actionable,row)
    }
    sort.Slice(actionable,func(i,j int) bool{return actionable[i].Domain<actionable[j].Domain})
    return actionable,counts
}

func discoveryReport(rawPath,datPath,reviewPath,outPath string) error {
    rows,err:=readDiscoveryTSV(rawPath);if err!=nil{return err}
    categories,err:=decode(datPath);if err!=nil{return err}
    if _,ok:=categories["RU"];!ok{return fmt.Errorf("candidate DAT missing RU")}
    if _,ok:=categories["BLOCK"];!ok{return fmt.Errorf("candidate DAT missing BLOCK")}
    reviews,err:=loadReviewDecisions(reviewPath);if err!=nil{return err}
    remaining,counts:=filterDiscoveryCandidates(rows,categories["RU"],categories["BLOCK"],reviews)
    var b strings.Builder
    fmt.Fprintln(&b,"# Newly discovered corporate-domain candidates — manual review only")
    fmt.Fprintln(&b,"")
    fmt.Fprintln(&b,"**Never auto-import these candidates into DIRECT or BLOCK.**")
    fmt.Fprintln(&b,"First-party TLS SAN and CSP signal a possible relation or dependency, not legal ownership.")
    fmt.Fprintln(&b,"Matching a CORE_CORPORATE origin prefix is additional hosting evidence, not proof")
    fmt.Fprintln(&b,"that a domain is owned by the same company. CSP may reference unrelated foreign vendors.")
    fmt.Fprintln(&b,"Only exact hosts are extracted; wildcards must not be widened into RootDomain.")
    fmt.Fprintln(&b,"")
    fmt.Fprintf(&b,"Observed: **%d**; already RU: **%d**; BLOCK overlap: **%d**; 4PDA excluded: **%d**; review hold: **%d**; review reject: **%d**; **new for review: %d**.\n",
        counts["observed"],counts["covered_RU"],counts["covered_BLOCK"],counts["4pda_excluded"],
        counts["review_hold"],counts["review_reject"],counts["new"])
    fmt.Fprintln(&b,"")
    fmt.Fprintln(&b,"| Domain | Signals | Corporate seed and evidence | CORE ASN and group (hosting signal only) | Public DNS IPs | DNS checked |")
    fmt.Fprintln(&b,"|---|---|---|---|---|---|")
    if len(remaining)==0{
        fmt.Fprintln(&b,"| — | No new uncovered candidates | — | — | — | — |")
    }
    for _,r:=range remaining {
        host:=safeMarkdown(r.Seeds+" — "+r.Evidence)
        asns:=safeMarkdown(r.ASNs+" "+r.Groups)
        fmt.Fprintf(&b,"| %c%s%c | %s | %s | %s | %s | %s |\n",
            96,r.Domain,96,safeMarkdown(r.Signals),host,asns,safeMarkdown(r.IPs),r.DNSChecked)
    }
    fmt.Fprintln(&b,"")
    fmt.Fprintln(&b,"## Next action")
    fmt.Fprintln(&b,"Verify first-party legal/domain ownership, service purpose, and minimal Full/Root scope.")
    fmt.Fprintln(&b,"Record source URL and rationale in versioned review before any new positive rule.")
    if err:=os.WriteFile(outPath,[]byte(b.String()),0644);err!=nil{return err}
    fmt.Printf("CORPORATE_DISCOVERY_FILTER observed=%d new=%d already_ru=%d block_overlap=%d holds=%d rejects=%d banned_4pda=%d report=%s\n",
        counts["observed"],counts["new"],counts["covered_RU"],counts["covered_BLOCK"],
        counts["review_hold"],counts["review_reject"],counts["4pda_excluded"],outPath)
    return nil
}
