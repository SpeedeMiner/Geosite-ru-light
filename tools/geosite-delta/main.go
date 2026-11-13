// Command geosite-delta compares actual decoded GeoSite protobufs.
// It reports semantic coverage differences, not merely the number of entries.
package main

import (
  "encoding/json"
  "errors"
  "fmt"
  "os"
  "sort"
  "strconv"
  "strings"

  router "github.com/v2fly/v2ray-core/v5/app/router/routercommon"
  "google.golang.org/protobuf/proto"
)

type rules struct {roots map[string]bool; full map[string]bool; opaque map[string]bool}
func decode(path string) (map[string]rules,error) {
  data,err:=os.ReadFile(path); if err!=nil{return nil,err}
  var db router.GeoSiteList
  if err=proto.Unmarshal(data,&db);err!=nil{return nil,err}
  out:=make(map[string]rules)
  for _,site:=range db.Entry {
    if site==nil {continue}
    cat:=strings.ToUpper(strings.TrimSpace(site.CountryCode))
    if cat=="" {return nil,fmt.Errorf("empty category in %s",path)}
    if _,duplicate:=out[cat];duplicate{return nil,fmt.Errorf("duplicate category %s in %s",cat,path)}
    r:=rules{roots:make(map[string]bool),full:make(map[string]bool),opaque:make(map[string]bool)}
    for _,d:=range site.Domain {
      if d==nil {continue}
      name:=strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d.Value)),".")
      switch d.Type {
      case router.Domain_RootDomain:
        r.roots[name]=true
      case router.Domain_Full:
        r.full[name]=true
      default:
        // Regex / Plain / future types cannot be reduced to suffix semantics.
        // Preserve their exact original encoding as a conservative regression gate.
        r.opaque[fmt.Sprintf("%v:%s",d.Type,strings.TrimSpace(d.Value))]=true
      }
    }
    out[cat]=r
  }
  return out,nil
}
func covered(r rules, domain string, isRoot bool) bool {
  if !isRoot && r.full[domain] {return true}
  v:=domain
  for {
    if r.roots[v] {return true}
    ix:=strings.IndexByte(v,'.')
    if ix<0 {return false}
    v=v[ix+1:]
  }
}
func differences(from,to rules) []string {
  var out []string
  for d:=range from.roots {if !covered(to,d,true) {out=append(out,"domain:"+d)}}
  for d:=range from.full {if !covered(to,d,false) {out=append(out,"full:"+d)}}
  for d:=range from.opaque {if !to.opaque[d] {out=append(out,"opaque:"+d)}}
  sort.Strings(out); return out
}
// rejectedSubtreeConflict catches any RU rule under a specifically forbidden
// apex (e.g. forum.4pda.to). Do not apply it to generic foreign CDN roots:
// independently approved RU services can use foreign shared CDN domains.
func rejectedSubtreeConflict(r rules, zone string) string {
  if covered(r,zone,false) {
    return "parent or apex covers "+zone
  }
  suffix:="."+zone
  for root:=range r.roots {
    if strings.HasSuffix(root,suffix) {
      return "domain:"+root
    }
  }
  for full:=range r.full {
    if strings.HasSuffix(full,suffix) {
      return "full:"+full
    }
  }
  return ""
}
// A pinned manifest is not an exact delta against the floating release.
// Every newly added effective RU rule must be pinned, while a previously
// approved rule may already be in latest-optimized. It must nevertheless
// remain covered by the candidate (and RootDomain may not degrade to Full).
func ruleCoveredByCandidate(candidate rules, rule string) bool {
  if strings.HasPrefix(rule,"domain:") {return covered(candidate,strings.TrimPrefix(rule,"domain:"),true)}
  if strings.HasPrefix(rule,"full:") {return covered(candidate,strings.TrimPrefix(rule,"full:"),false)}
  return false
}
type pendingRUReview struct { rules []string }
func (e *pendingRUReview) Error() string {
  return fmt.Sprintf("%d unreviewed effective new RU rule(s): %s",len(e.rules),strings.Join(e.rules,", "))
}

func verifyReviewedAdditions(path string, actual []string, candidate rules) error {
  data,err:=os.ReadFile(path);if err!=nil{return err}
  approved:=make(map[string]bool)
  for i,line:=range strings.Split(string(data),"\n"){
    line=strings.TrimSpace(line)
    if line==""||strings.HasPrefix(line,"#"){continue}
    if !strings.HasPrefix(line,"domain:")&&!strings.HasPrefix(line,"full:"){
      return fmt.Errorf("invalid approved RU rule at line %d: %s",i+1,line)
    }
    if approved[line]{return fmt.Errorf("duplicate approved rule at line %d: %s",i+1,line)}
    approved[line]=true
  }
  if len(approved)==0{return fmt.Errorf("empty approved RU manifest")}
  actualSeen:=make(map[string]bool)
  var pending []string
  for _,rule:=range actual{
    if actualSeen[rule]{return fmt.Errorf("duplicate effective new RU rule %s",rule)}
    actualSeen[rule]=true
    if !approved[rule]{
      // An unsupported rule type is a hard error, not an ordinary
      // upstream addition awaiting review.
      if !strings.HasPrefix(rule,"domain:") && !strings.HasPrefix(rule,"full:"){
        return fmt.Errorf("unsupported new effective RU rule: %q",rule)
      }
      pending=append(pending,rule)
    }
  }
  for rule:=range approved{
    if !ruleCoveredByCandidate(candidate,rule){
      return fmt.Errorf("previously approved RU rule no longer effectively covered: %s",rule)
    }
  }
  if len(pending)>0{return &pendingRUReview{rules:pending}}
  return nil
}
// External candidate inventories are only reviewed here; they are NEVER imported.
type externalCandidate struct {
  Sources []string `json:"sources"`
  Reason string `json:"reason"`
}
type externalInventory struct {
  Domains map[string]externalCandidate `json:"domains"`
}
type reviewDecision struct {status string; rationale string}
func loadReviewDecisions(path string) (map[string]reviewDecision,error) {
  data,err:=os.ReadFile(path);if err!=nil{return nil,err}
  reviews:=make(map[string]reviewDecision)
  for n,line:=range strings.Split(string(data),"\n"){
    line=strings.TrimSpace(line)
    if line==""||strings.HasPrefix(line,"#"){continue}
    fields:=strings.SplitN(line,"\t",3)
    if len(fields)!=3{return nil,fmt.Errorf("invalid review row %d",n+1)}
    domain:=strings.ToLower(strings.TrimSpace(fields[0]))
    decision:=strings.TrimSpace(fields[1])
    rationale:=strings.TrimSpace(fields[2])
    if domain==""||strings.ContainsAny(domain," |/")||rationale==""{return nil,fmt.Errorf("invalid review domain/evidence at row %d",n+1)}
    if decision!="reject"&&decision!="hold"&&decision!="confirmed"{return nil,fmt.Errorf("invalid decision at row %d: %s",n+1,decision)}
    if _,ok:=reviews[domain];ok{return nil,fmt.Errorf("duplicate review: %s",domain)}
    reviews[domain]=reviewDecision{decision,rationale}
  }
  return reviews,nil
}
func reportExternalCandidates(input, path, reviewPath string, categories map[string]rules) error {
  contents, err:=os.ReadFile(input);if err!=nil{return err}
  var inventory externalInventory
  if err:=json.Unmarshal(contents,&inventory);err!=nil{return err}
  if len(inventory.Domains)==0{return fmt.Errorf("empty candidate inventory")}
  reviews,err:=loadReviewDecisions(reviewPath);if err!=nil{return err}
  ru:=categories["RU"]; block:=categories["BLOCK"]
  // User-selected no-DIRECT subtree. Independent of external inventory and
  // review file: removing a TSV line cannot weaken this routing policy.
  for _,domain:=range []string{"4pda.to","www.4pda.to"} {
    if reviews[domain].status!="reject" {
      return fmt.Errorf("mandatory no-DIRECT policy missing reject decision for %s",domain)
    }
  }
  if conflict:=rejectedSubtreeConflict(ru,"4pda.to");conflict!="" {
    return fmt.Errorf("4pda.to no-DIRECT subtree policy violated: %s",conflict)
  }
  for domain,review:=range reviews {
    isRU:=covered(ru,domain,false)
    // A generic reject is exact to this domain, NOT a blanket ban for all
    // descendants: shared Akamai/Cloudflare CDNs can host RU-specific services.
    if review.status=="reject"&&isRU {
      return fmt.Errorf("rejected external domain %s is unexpectedly covered by RU",domain)
    }
    if review.status=="hold"&&isRU{
      return fmt.Errorf("external domain %s is on HOLD pending routing approval but has RU coverage",domain)
    }
    if review.status=="confirmed"&&!isRU{
      return fmt.Errorf("confirmed candidate %s is missing from RU",domain)
    }
  }
  names:=make([]string,0,len(inventory.Domains))
  for domain:=range inventory.Domains{names=append(names,domain)}
  sort.Strings(names)
  var b strings.Builder
  fmt.Fprintln(&b,"# External domain candidates — audit only (no automatic DIRECT import)")
  fmt.Fprintln(&b,"")
  fmt.Fprintln(&b,"Source: w1zardz/amnezia-vpn-russia-split-tunneling data/external-candidates.json; upstream metadata may be stale.")
  fmt.Fprintln(&b,"DNS/ownership is **not** verified by this report. Review every uncovered candidate manually.")
  fmt.Fprintln(&b,"")
  fmt.Fprintln(&b,"| Domain | Coverage status | Review decision | Sources | Upstream rejection reason | Review rationale |")
  fmt.Fprintln(&b,"|---|---|---|---|---|---|")
  count:=map[string]int{}
  for _,raw:=range names{
    d:=strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw),"."))
    if d=="" || strings.ContainsAny(d," |\\\t\r\n") {continue}
    candidate:=inventory.Domains[raw]
    status:="manual_review_uncovered"
    if covered(ru,d,false){status="already_covered_RU"
    }else if covered(block,d,false){status="covered_BLOCK_review_conflict"
    }else if candidate.Reason!=""{status="uncovered_with_upstream_warning"}
    count[status]++
    review:=reviews[d]
    reviewLabel:=review.status
    if reviewLabel==""{reviewLabel="unreviewed"}
    count["decision_"+reviewLabel]++
    if status=="manual_review_uncovered" && reviewLabel=="unreviewed" {
      count["needs_unreviewed_manual_triage"]++
    }
    if status=="uncovered_with_upstream_warning" && reviewLabel=="unreviewed" {
      count["needs_unreviewed_warning_triage"]++
    }
    if status=="manual_review_uncovered" {
      fmt.Printf("CANDIDATE_REVIEW %s sources=%s\n",d,strings.Join(candidate.Sources,","))
    }
    why:=strings.ReplaceAll(candidate.Reason,"|","/")
    sources:=strings.Join(candidate.Sources,", ")
    rationale:=strings.ReplaceAll(review.rationale,"|","/")
    fmt.Fprintf(&b,"| `%s` | %s | %s | %s | %s | %s |\n",d,status,reviewLabel,sources,why,rationale)
  }
  if err:=os.WriteFile(path,[]byte(b.String()),0644);err!=nil{return err}
  fmt.Printf("EXTERNAL_CANDIDATES total=%d",len(inventory.Domains))
  for _,k:=range []string{"already_covered_RU","covered_BLOCK_review_conflict","uncovered_with_upstream_warning","manual_review_uncovered"}{
    fmt.Printf(" %s=%d",k,count[k])
  }
  for _,k:=range []string{"decision_confirmed","decision_hold","decision_reject","decision_unreviewed"} {fmt.Printf(" %s=%d",k,count[k])}
  for _,k:=range []string{"needs_unreviewed_manual_triage","needs_unreviewed_warning_triage"} {
    fmt.Printf(" %s=%d",k,count[k])
  }
  fmt.Println()
  return nil
}
func main(){
  if len(os.Args)>1 && os.Args[1]=="discovery-review" {
    if len(os.Args)!=6 && len(os.Args)!=7 {
      fmt.Fprintln(os.Stderr,"usage: geosite-delta discovery-review evidence.tsv candidate.dat decisions.tsv report.md [queue.tsv]")
      os.Exit(2)
    }
    if err:=discoveryReport(os.Args[2],os.Args[3],os.Args[4],os.Args[5],os.Args[6:]...);err!=nil{panic(err)}
    return
  }
  if len(os.Args)==6 && os.Args[1]=="discovery-inventory" {
    if err:=pendingDiscoveryInventory(os.Args[2],os.Args[3],os.Args[4],os.Args[5]);err!=nil{panic(err)}
    return
  }
  if len(os.Args)!=4 && len(os.Args)!=5 && len(os.Args)!=8 {fmt.Fprintln(os.Stderr,"usage: geosite-delta release.dat candidate.dat report.md [approved-effective-RU.txt | external-candidates.json external-review.md decisions.tsv approved-effective-RU.txt]");os.Exit(2)}
  old,err:=decode(os.Args[1]);if err!=nil{panic(err)}
  now,err:=decode(os.Args[2]);if err!=nil{panic(err)}
  var b,details strings.Builder
  fmt.Fprintln(&b,"# Semantic comparison: release DAT vs candidate")
  fmt.Fprintln(&b,"")
  fmt.Fprintln(&b,"Rules are compared by effective suffix/full-domain coverage. Regex/Plain or future rule types, if any, are compared conservatively by exact encoding; no inferred DNS ownership.")
  fmt.Fprintln(&b,"")
  fmt.Fprintln(&b,"| Category | Release rules | Candidate rules | Newly covered rules | No longer covered rules |")
  fmt.Fprintln(&b,"|---|---:|---:|---:|---:|")
  cats:=make(map[string]bool)
  for c:=range old{cats[c]=true};for c:=range now{cats[c]=true}
  keys:=make([]string,0,len(cats));for c:=range cats{keys=append(keys,c)};sort.Strings(keys)
  lostRU:=0
  var addedRU []string
  blockAdded,blockLost:=0,0
  var changedNonRU []string
  for _,c:=range keys {
    a,z:=old[c],now[c]
    added:=differences(z,a);lost:=differences(a,z)
    fmt.Printf("DELTA %s: release=%d candidate=%d newly_covered=%d lost=%d\n",c,len(a.roots)+len(a.full)+len(a.opaque),len(z.roots)+len(z.full)+len(z.opaque),len(added),len(lost))
    if c!="RU" && (len(added)>0 || len(lost)>0 || len(a.roots)+len(a.full)+len(a.opaque)!=len(z.roots)+len(z.full)+len(z.opaque)) {
      changedNonRU=append(changedNonRU,c)
    }
    if c=="BLOCK" {
      // v11 is RU expansion only: BLOCK changes require a separate review.
      blockAdded,blockLost=len(added),len(lost)
    }
    if c=="RU" {
      addedRU=added
      lostRU=len(lost)
      for _,v:=range added {fmt.Printf("RU_NEW %s\n",v)}
      for _,v:=range lost {fmt.Printf("RU_LOST %s\n",v)}
    }
    fmt.Fprintf(&b,"| %s | %d | %d | %d | %d |\n",c,len(a.roots)+len(a.full)+len(a.opaque),len(z.roots)+len(z.full)+len(z.opaque),len(added),len(lost))
    fmt.Fprintf(&details,"\n## %s — added effective rules (%d)\n\n",c,len(added))
    for _,v:=range added {fmt.Fprintln(&details,"- `"+v+"`")}
    fmt.Fprintf(&details,"\n## %s — no longer covered (%d)\n\n",c,len(lost))
    for _,v:=range lost {fmt.Fprintln(&details,"- `"+v+"`")}
  }
  if err:=os.WriteFile(os.Args[3],[]byte(b.String()+details.String()),0644);err!=nil{panic(err)}
  fmt.Print(b.String())
  fmt.Printf("Complete report saved: %s\n",os.Args[3])
  // The initial v11.2 promotion pins the known v11.1 DAT delta. Normal
  // later updates still use the cumulative approvals and the BLOCK gate.
  if raw:=os.Getenv("GEOSITE_EXPECTED_RU_ADDITIONS");raw!="" {
    expected,err:=strconv.Atoi(raw)
    if err!=nil || expected<0 || len(addedRU)!=expected || len(changedNonRU)>0 {
      fmt.Fprintf(os.Stderr,"ERROR: release promotion expected %q RU additions and non-RU parity; got %d RU additions, changed non-RU categories: %v\n",raw,len(addedRU),changedNonRU)
      os.Exit(1)
    }
  }
  if lostRU>0 {
    fmt.Fprintf(os.Stderr,"ERROR: %d release RU rules no longer covered; review before merge\n",lostRU)
    os.Exit(1)
  }
  if blockAdded>0 || blockLost>0 {
    fmt.Fprintf(os.Stderr,"ERROR: BLOCK policy changed without separate approval: %d newly covered, %d lost\n",blockAdded,blockLost)
    os.Exit(1)
  }
  if len(os.Args)==5 {
    if err:=verifyReviewedAdditions(os.Args[4],addedRU,now["RU"]);err!=nil{
      var pending *pendingRUReview
      if errors.As(err,&pending) {
        fmt.Fprintf(os.Stderr,"PENDING_RU_REVIEW: %v\n",pending)
        os.Exit(3)
      }
      fmt.Fprintf(os.Stderr,"ERROR: %v\n",err)
      os.Exit(1)
    }
    if len(addedRU)>0 {
      fmt.Printf("PRODUCTION_RU_APPROVAL count=%d exact_match=true mode=reviewed_additions\n",len(addedRU))
    }else{
      fmt.Println("PRODUCTION_RU_APPROVAL count=0 mode=idempotent_release")
    }
  }
  if len(os.Args)==8 {
    if err:=reportExternalCandidates(os.Args[4],os.Args[5],os.Args[6],now);err!=nil{panic(err)}
    if err:=verifyReviewedAdditions(os.Args[7],addedRU,now["RU"]);err!=nil{panic(err)}
    if len(addedRU)==0 {
      fmt.Println("APPROVED_RU_NEW count=0 mode=published-release-parity")
    }else{
      fmt.Printf("APPROVED_RU_NEW count=%d exact_match=true\n",len(addedRU))
    }
  }
}
