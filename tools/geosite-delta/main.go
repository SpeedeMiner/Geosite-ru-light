// Command geosite-delta compares actual decoded GeoSite protobufs.
// It reports semantic coverage differences, not merely the number of entries.
package main

import (
  "fmt"
  "encoding/json"
  "os"
  "sort"
  "strings"

  router "github.com/v2fly/v2ray-core/v5/app/router/routercommon"
  "google.golang.org/protobuf/proto"
)

type rules struct {roots map[string]bool; full map[string]bool}
func decode(path string) (map[string]rules,error) {
  data,err:=os.ReadFile(path); if err!=nil{return nil,err}
  var db router.GeoSiteList
  if err=proto.Unmarshal(data,&db);err!=nil{return nil,err}
  out:=make(map[string]rules)
  for _,site:=range db.Entry {
    if site==nil {continue}
    cat:=strings.ToUpper(strings.TrimSpace(site.CountryCode))
    r:=rules{make(map[string]bool),make(map[string]bool)}
    for _,d:=range site.Domain {
      if d==nil {continue}
      name:=strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d.Value)),".")
      if d.Type==router.Domain_RootDomain {r.roots[name]=true}
      if d.Type==router.Domain_Full {r.full[name]=true}
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
  sort.Strings(out); return out
}
// External candidate inventories are only reviewed here; they are NEVER imported.
type externalCandidate struct {
  Sources []string `json:"sources"`
  Reason string `json:"reason"`
}
type externalInventory struct {
  Domains map[string]externalCandidate `json:"domains"`
}
func reportExternalCandidates(input, path string, categories map[string]rules) error {
  contents, err:=os.ReadFile(input);if err!=nil{return err}
  var inventory externalInventory
  if err:=json.Unmarshal(contents,&inventory);err!=nil{return err}
  if len(inventory.Domains)==0{return fmt.Errorf("empty candidate inventory")}
  ru:=categories["RU"]; block:=categories["BLOCK"]
  names:=make([]string,0,len(inventory.Domains))
  for domain:=range inventory.Domains{names=append(names,domain)}
  sort.Strings(names)
  var b strings.Builder
  fmt.Fprintln(&b,"# External domain candidates — audit only (no automatic DIRECT import)")
  fmt.Fprintln(&b,"")
  fmt.Fprintln(&b,"Source: w1zardz/amnezia-vpn-russia-split-tunneling data/external-candidates.json; upstream metadata may be stale.")
  fmt.Fprintln(&b,"DNS/ownership is **not** verified by this report. Review every uncovered candidate manually.")
  fmt.Fprintln(&b,"")
  fmt.Fprintln(&b,"| Domain | Status | Sources | Upstream rejection reason |")
  fmt.Fprintln(&b,"|---|---|---|---|")
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
    why:=strings.ReplaceAll(candidate.Reason,"|","/")
    sources:=strings.Join(candidate.Sources,", ")
    fmt.Fprintf(&b,"| `%s` | %s | %s | %s |\n",d,status,sources,why)
  }
  if err:=os.WriteFile(path,[]byte(b.String()),0644);err!=nil{return err}
  fmt.Printf("EXTERNAL_CANDIDATES total=%d",len(inventory.Domains))
  for _,k:=range []string{"already_covered_RU","covered_BLOCK_review_conflict","uncovered_with_upstream_warning","manual_review_uncovered"}{
    fmt.Printf(" %s=%d",k,count[k])
  }
  fmt.Println()
  return nil
}
func main(){
  if len(os.Args)!=4 && len(os.Args)!=6 {fmt.Fprintln(os.Stderr,"usage: geosite-delta release.dat candidate.dat report.md [external-candidates.json external-review.md]");os.Exit(2)}
  old,err:=decode(os.Args[1]);if err!=nil{panic(err)}
  now,err:=decode(os.Args[2]);if err!=nil{panic(err)}
  var b strings.Builder
  fmt.Fprintln(&b,"# Semantic comparison: release DAT vs v11 candidate")
  fmt.Fprintln(&b,"")
  fmt.Fprintln(&b,"Rules are compared by effective suffix/full-domain coverage; no inferred DNS ownership.")
  fmt.Fprintln(&b,"")
  fmt.Fprintln(&b,"| Category | Release rules | Candidate rules | Newly covered rules | No longer covered rules |")
  fmt.Fprintln(&b,"|---|---:|---:|---:|---:|")
  cats:=make(map[string]bool)
  for c:=range old{cats[c]=true};for c:=range now{cats[c]=true}
  keys:=make([]string,0,len(cats));for c:=range cats{keys=append(keys,c)};sort.Strings(keys)
  lostRU:=0
  for _,c:=range keys {
    a,z:=old[c],now[c]
    added:=differences(z,a);lost:=differences(a,z)
    fmt.Printf("DELTA %s: release=%d candidate=%d newly_covered=%d lost=%d\n",c,len(a.roots)+len(a.full),len(z.roots)+len(z.full),len(added),len(lost))
    if c=="RU" {
      lostRU=len(lost)
      for _,v:=range added {fmt.Printf("RU_NEW %s\n",v)}
      for _,v:=range lost {fmt.Printf("RU_LOST %s\n",v)}
    }
    fmt.Fprintf(&b,"| %s | %d | %d | %d | %d |\n",c,len(a.roots)+len(a.full),len(z.roots)+len(z.full),len(added),len(lost))
    fmt.Fprintf(&b,"\n## %s — added effective rules (%d)\n\n",c,len(added))
    for _,v:=range added {fmt.Fprintln(&b,"- `"+v+"`")}
    fmt.Fprintf(&b,"\n## %s — no longer covered (%d)\n\n",c,len(lost))
    for _,v:=range lost {fmt.Fprintln(&b,"- `"+v+"`")}
  }
  if err:=os.WriteFile(os.Args[3],[]byte(b.String()),0644);err!=nil{panic(err)}
  fmt.Print(strings.SplitN(b.String(),"\n## ",2)[0])
  fmt.Printf("Complete report saved: %s\n",os.Args[3])
  if len(os.Args)==6 {
    if err:=reportExternalCandidates(os.Args[4],os.Args[5],now);err!=nil{panic(err)}
  }
  if lostRU>0 {
    fmt.Fprintf(os.Stderr,"ERROR: %d release RU rules no longer covered; review before merge\n",lostRU)
    os.Exit(1)
  }
}
