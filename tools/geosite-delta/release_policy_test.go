package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	router "github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

func TestLockedReleaseGate(t *testing.T) {
	t.Setenv("GEOSITE_EXPECTED_RU_ADDITIONS", "")
	dir := t.TempDir()
	path := func(name string) string { return filepath.Join(dir, name) }
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(path(name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	type T = router.Domain_Type
	const (
		suffix T = router.Domain_RootDomain
		exact  T = router.Domain_Full
	)
	rule := func(typ T, name string) *router.Domain {
		return &router.Domain{Type: typ, Value: name}
	}
	makeDat := func(file string, ru, apple []*router.Domain, keepApple bool) {
		t.Helper()
		sites := []*router.GeoSite{
			{CountryCode: "RU", Domain: ru},
			{CountryCode: "BLOCK", Domain: []*router.Domain{rule(suffix, "blocked.example")}},
		}
		if keepApple {
			sites = append(sites, &router.GeoSite{CountryCode: "APPLE", Domain: apple})
		}
		raw, err := proto.Marshal(&router.GeoSiteList{Entry: sites})
		if err != nil {
			t.Fatal(err)
		}
		write(file, string(raw))
	}
	base := []*router.Domain{rule(suffix, "existing.example")}
	hydra := []*router.Domain{rule(suffix, "old.apple.example")}
	ledger := "4pda.to\treject\tuser rule\nwww.4pda.to\treject\tuser rule\n"
	makeDat("locked.dat", base, hydra, true)
	write("decisions.tsv", ledger)
	write("approvals.txt", "domain:existing.example\n")
	check := func() error {
		return checkRelease([]string{path("rolling.dat"), path("locked.dat"), path("candidate.dat"),
			path("delta.md"), path("approvals.txt"), path("decisions.tsv")})
	}
	for _, tc := range []struct {
		name, want, decisions string
		rolling, candidate    []*router.Domain
		apple                 []*router.Domain
		present, pending      bool
	}{
		{"unchanged", "", ledger, base, base, hydra, true, false},
		{"new RU goes to Draft", "unreviewed", ledger, base, append(base, rule(suffix, "new.example")), hydra, true, true},
		{"Hydra addition blocks", "APPLE", ledger, base, base, append(hydra, rule(suffix, "new.apple.example")), true, false},
		{"Hydra removal blocks", "APPLE", ledger, base, base, nil, true, false},
		{"Hydra type change blocks", "APPLE", ledger, base, base, []*router.Domain{rule(exact, "old.apple.example")}, true, false},
		{"Hydra category disappears", "APPLE", ledger, base, base, nil, false, false},
		{"held domain masks pending state", "HOLD", ledger + "new.example\thold\tevidence\n", base, append(base, rule(suffix, "new.example")), hydra, true, false},
		{"rejected name covered by ancestor", "rejected", ledger + "a.new.example\treject\tevidence\n", base, append(base, rule(suffix, "new.example")), hydra, true, false},
		{"shared CDN child remains eligible", "unreviewed", ledger + "cdn.example\treject\tevidence\n", base, append(base, rule(exact, "a.cdn.example")), hydra, true, true},
		{"confirmed absent", "missing", ledger + "new.example\tconfirmed\tevidence\n", base, base, hydra, true, false},
		{"Kick parent not allowed", "stream.kick.com", ledger, base, append(base, rule(suffix, "kick.com")), hydra, true, false},
		{"4pda descendant not allowed", "4pda.to", ledger, base, append(base, rule(exact, "other.4pda.to")), hydra, true, false},
		{"rolling contamination no delta", "locked release policy", ledger, append(base, rule(suffix, "bad.example")), append(base, rule(suffix, "bad.example")), hydra, true, false},
		{"rolling contamination with fresh delta", "rolling baseline contains", ledger, append(base, rule(suffix, "bad.example")), append(base, rule(suffix, "bad.example"), rule(suffix, "new.example")), hydra, true, false},
		{"rolling missing locked RU", "locked release floor", ledger, nil, nil, hydra, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			write("decisions.tsv", tc.decisions)
			makeDat("rolling.dat", tc.rolling, hydra, true)
			makeDat("candidate.dat", tc.candidate, tc.apple, tc.present)
			err := check()
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("wanted %q, got %v", tc.want, err)
			}
			var pending *pendingRUReview
			if errors.As(err, &pending) != tc.pending {
				t.Fatalf("wrong schedule classification: %v", err)
			}
		})
	}
	t.Run("approved addition remains approved after publication", func(t *testing.T) {
		write("decisions.tsv", ledger)
		write("approvals.txt", "domain:existing.example\nfull:new.example\n")
		candidate := append(base, rule(exact, "new.example"))
		makeDat("rolling.dat", base, hydra, true)
		makeDat("candidate.dat", candidate, hydra, true)
		if err := check(); err != nil {
			t.Fatal(err)
		}
		makeDat("rolling.dat", candidate, hydra, true)
		if err := check(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestProtectedCategoryDetectsSameCoverageTypeChanges(t *testing.T) {
	old := map[string]rules{"APPLE": {
		roots: map[string]bool{"apple.example": true},
		full:  map[string]bool{"foo.apple.example": true},
	}}
	now := map[string]rules{"APPLE": {
		roots: map[string]bool{"apple.example": true},
		full:  map[string]bool{"bar.apple.example": true},
	}}
	if len(differences(old["APPLE"], now["APPLE"])) != 0 ||
		len(differences(now["APPLE"], old["APPLE"])) != 0 {
		t.Fatal("fixture must keep equal effective coverage")
	}
	if got := changedProtectedCategories(old, now); len(got) != 1 || got[0] != "APPLE" {
		t.Fatalf("typed rules changed without detection: %v", got)
	}
}
