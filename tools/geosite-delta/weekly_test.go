package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	router "github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

// Exercise actual comparator exit codes, including os.Exit, in a subprocess.
func TestWeeklyGateSubprocess(t *testing.T) {
	if os.Getenv("GEOSITE_WEEKLY_GATE_TEST") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			main()
			os.Exit(0)
		}
	}
	t.Fatal("missing comparator arguments")
}

func TestWeeklyGateClassification(t *testing.T) {
	dir := t.TempDir()
	path := func(name string) string { return filepath.Join(dir, name) }
	write := func(name string, content []byte) {
		t.Helper()
		if err := os.WriteFile(path(name), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	site := func(code string, names ...string) *router.GeoSite {
		s := &router.GeoSite{CountryCode: code}
		for _, name := range names {
			s.Domain = append(s.Domain, &router.Domain{Type: router.Domain_RootDomain, Value: name})
		}
		return s
	}
	dat := func(name string, sites ...*router.GeoSite) {
		t.Helper()
		raw, err := proto.Marshal(&router.GeoSiteList{Entry: sites})
		if err != nil {
			t.Fatal(err)
		}
		write(name, raw)
	}
	oldRU := site("RU", "existing.example")
	oldBlock := site("BLOCK", "blocked.example")
	dat("old.dat", oldRU, oldBlock)
	for _, tc := range []struct {
		name, approved string
		ru, block      *router.GeoSite
		want           int
	}{
		{"equal", "domain:existing.example", oldRU, oldBlock, 0},
		{"reviewed", "domain:existing.example\ndomain:new.example", site("RU", "existing.example", "new.example"), oldBlock, 0},
		{"pending", "domain:existing.example", site("RU", "existing.example", "new.example", "second.example"), oldBlock, 3},
		{"RU regression", "domain:existing.example", site("RU", "new.example"), oldBlock, 1},
		{"BLOCK changed", "domain:existing.example", site("RU", "existing.example", "new.example"), site("BLOCK", "new-block.example"), 1},
		{"invalid approvals", "bad", site("RU", "existing.example", "new.example"), oldBlock, 1},
		{"pinned rule lost", "domain:existing.example\ndomain:missing.example", site("RU", "existing.example", "new.example"), oldBlock, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dat("candidate.dat", tc.ru, tc.block)
			write("approved.txt", []byte(tc.approved+"\n"))
			cmd := exec.Command(os.Args[0], "-test.run=^TestWeeklyGateSubprocess$", "--",
				path("old.dat"), path("candidate.dat"), path("report.md"), path("approved.txt"))
			cmd.Env = append(os.Environ(), "GEOSITE_WEEKLY_GATE_TEST=1", "GEOSITE_EXPECTED_RU_ADDITIONS=")
			if out, err := cmd.CombinedOutput(); cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != tc.want {
				t.Fatalf("expected exit %d, got %v\n%s", tc.want, err, out)
			}
			report, err := os.ReadFile(path("report.md"))
			if err != nil {
				t.Fatal(err)
			}
			head, _, _ := strings.Cut(string(report), "\n## ")
			if !strings.Contains(head, "| RU |") || !strings.Contains(head, "| BLOCK |") {
				t.Fatalf("incomplete markdown summary:\n%s", report)
			}
			if tc.want == 3 && (!strings.Contains(string(report), "domain:new.example") || !strings.Contains(string(report), "domain:second.example")) {
				t.Fatalf("pending additions missing from report:\n%s", report)
			}
		})
	}
}
