package main

import (
  "os"
  "path/filepath"
  "testing"

  router "github.com/v2fly/v2ray-core/v5/app/router/routercommon"
  "google.golang.org/protobuf/proto"
)

func TestDifferencesRespectsRootAndFullSemantics(t *testing.T) {
  old := rules{
    roots: map[string]bool{"nested.example.org": true},
    full: map[string]bool{"exact.example.net": true},
    opaque: map[string]bool{},
  }
  candidate := rules{
    roots: map[string]bool{"example.org": true, "example.net": true},
    full: map[string]bool{},
    opaque: map[string]bool{},
  }
  if got:=differences(old,candidate);len(got)!=0 {
    t.Fatalf("ancestor roots must cover suffix and exact rules: %v",got)
  }
  // A RootDomain in the release is NOT covered by a candidate Full rule.
  newExact := rules{roots:map[string]bool{},full:map[string]bool{"nested.example.org":true},opaque:map[string]bool{}}
  if got:=differences(old,newExact);len(got)!=2 {
    t.Fatalf("Full rule must not replace a suffix or unrelated exact rule: %v",got)
  }
}

func TestOpaqueRuleRegressionCannotBeHidden(t *testing.T) {
  old := rules{roots:map[string]bool{},full:map[string]bool{},opaque:map[string]bool{"Regex:^foo[0-9]+$":true}}
  now := rules{roots:map[string]bool{},full:map[string]bool{},opaque:map[string]bool{}}
  got:=differences(old,now)
  if len(got)!=1 || got[0]!="opaque:Regex:^foo[0-9]+$" {
    t.Fatalf("lost Regex rule must be visible: %v",got)
  }
}

func TestDecodePreservesOtherTypesAndRejectsDuplicateCategories(t *testing.T) {
  directory:=t.TempDir()
  write:=func(name string, sites ...*router.GeoSite) string {
    t.Helper()
    payload,err:=proto.Marshal(&router.GeoSiteList{Entry:sites});if err!=nil{t.Fatal(err)}
    path:=filepath.Join(directory,name)
    if err:=os.WriteFile(path,payload,0600);err!=nil{t.Fatal(err)}
    return path
  }
  ru:=&router.GeoSite{CountryCode:"RU",Domain:[]*router.Domain{
    {Type:router.Domain_Type(1),Value:"^Foo[0-9]+$"},
    {Type:router.Domain_RootDomain,Value:"example.ru"},
  }}
  decoded,err:=decode(write("single.dat",ru))
  if err!=nil{t.Fatal(err)}
  if len(decoded["RU"].opaque)!=1 || len(decoded["RU"].roots)!=1 {
    t.Fatalf("expected both Regex and RootDomain: %+v",decoded["RU"])
  }
  _,err=decode(write("duplicate.dat",ru,&router.GeoSite{CountryCode:"ru"}))
  if err==nil{t.Fatal("duplicate RU categories must be rejected")}
}
