package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	router "github.com/v2fly/v2ray-core/v5/app/router/routercommon"
)

func TestMain(m *testing.M) {
	var err error
	path := os.Getenv("RU_APPROVED_MANIFEST")
	if path == "" {
		path = filepath.Join("..", "..", "data", "v11-approved-effective-ru.txt")
	}
	exactRUPositiveHosts, err = loadExactRUPositiveHosts(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	approvedExactByAncestor = indexExactAncestors(exactRUPositiveHosts)
	os.Exit(m.Run())
}

func TestReviewedManifestExactHostScope(t *testing.T) {
	const host = "seller.ozon.am"
	if !exactRUPositiveHosts[host] || exactRUPositiveHosts["ozon.am"] ||
		exactRUPositiveHosts["nested."+host] {
		t.Fatal("approved policy widened an exact hostname")
	}
	ru := &router.GeoSite{CountryCode: "RU"}
	if !addPositiveRule(ru, make(map[string]bool), host) ||
		len(ru.Domain) != 1 || ru.Domain[0].Type != router.Domain_Full {
		t.Fatal("reviewed local host did not build as Full")
	}
}

func TestExactManifestRejectsInvalidRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reviewed.txt")
	for _, data := range []string{
		"domain:example.com\n",
		"full:EXAMPLE.com\n",
		"full:a.example.com\nfull:a.example.com\n",
		"full:www.4pda.to\n",
		"full:*.example.com\n",
		"domain:example.com\nfull:api.example.com\n",
		"domain:api.example.com\nfull:api.example.com\n",
	} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadExactRUPositiveHosts(path); err == nil {
			t.Fatalf("invalid Full policy accepted: %q", data)
		}
	}
}

func TestRussianFamilyTLDsCollapseIncludingUnicode(t *testing.T) {
	cases := []string{
		"service.ru",
		"service.su",
		"service.xn--p1ai",
		"service.рф",
		"service.moscow",
		"service.москва",
		"service.tatar",
		"service.xn--p1acf",
		"service.рус",
		"service.xn--d1acj3b",
		"service.дети",
		"service.xn--c1avg",
		"service.орг",
		"service.xn--j1aef",
		"service.ком",
		"service.xn--80aswg",
		"service.сайт",
		"service.xn--80asehdb",
		"service.онлайн",
		"service.yandex",
	}

	for _, domain := range cases {
		if !isRussianTLD(domain) {
			t.Fatalf("expected Russian-family TLD: %q", domain)
		}
	}
}

func TestSberIsCompactServiceRootButNotRussianTLD(t *testing.T) {
	if isRussianTLD("service.sber") {
		t.Fatalf("sber must not be classified as a TLD")
	}
	if !isCoveredByCompactServiceRoot("service.sber") {
		t.Fatalf("service.sber must be covered by compact service root sber")
	}
	if !isCompactRussianRoot("sber") || !isCompactRussianServiceRoot("sber") {
		t.Fatalf("sber must be configured as a compact service root")
	}
}

func TestForeignPositiveDomainsAreNotPromotedToRU(t *testing.T) {
	ru := &router.GeoSite{CountryCode: "RU"}
	seen := make(map[string]bool)
	if addRoot(ru, seen, "stream.kick.com") {
		t.Fatal("foreign streaming CDN leaked into RU")
	}
	if len(ru.Domain) != 0 {
		t.Fatal("excluded rule was added to RU")
	}
	if !addRoot(ru, seen, "ddos-guard.net") {
		t.Fatal("legitimate RU service was rejected")
	}
}

func TestNo4PDADirectInScheduledAndPRBuild(t *testing.T) {
	for _, value := range []string{
		"4pda.to", "www.4pda.to", "forum.4pda.to",
		"cdn.static.4pda.to", "to",
	} {
		ru := &router.GeoSite{CountryCode: "RU"}
		seen := make(map[string]bool)
		if !forbidden4PDAInRU(router.Domain_RootDomain, value) {
			t.Fatalf("forbidden 4PDA coverage was not recognized: %s", value)
		}
		if addRoot(ru, seen, value) || len(ru.Domain) != 0 {
			t.Fatalf("forbidden 4PDA root leaked into RU: %s", value)
		}
	}
	for _, value := range []string{"4pda.ru", "not4pda.to", "foo4pda.to"} {
		ru := &router.GeoSite{CountryCode: "RU"}
		if forbidden4PDAInRU(router.Domain_RootDomain, value) {
			t.Fatalf("unrelated domain falsely forbidden: %s", value)
		}
		if !addRoot(ru, make(map[string]bool), value) {
			t.Fatalf("unrelated RU candidate rejected: %s", value)
		}
	}
	if !forbidden4PDAInRU(router.Domain_Full, "forum.4pda.to") {
		t.Fatal("Full subdomain must also be forbidden")
	}
	if forbidden4PDAInRU(router.Domain_Full, "to") {
		t.Fatal("Full 'to' is not a suffix root and cannot cover 4pda.to")
	}
}

func TestV2flyAndTextPositiveSourcesCannotWidenVendorExactEndpoints(t *testing.T) {
	ru := &router.GeoSite{CountryCode: "RU"}
	seen := make(map[string]bool)
	for _, value := range []string{
		"prod.ntprog.com", "uat.ntprog.com",
		"msk-prod-gate.ntprog.com", "muat-gate.ntprog.com",
	} {
		if !addPositiveRule(ru, seen, value) {
			t.Fatalf("first positive import did not add Full %s", value)
		}
		if addPositiveRule(ru, seen, value) {
			t.Fatalf("duplicate Full widened vendor domain %s", value)
		}
		if !exactRUPositiveHosts[value] {
			t.Fatalf("unexpected exact-host list difference %s", value)
		}
	}
	ru.Domain, _ = pruneCoveredDomains(ru.Domain)
	if len(ru.Domain) != 4 {
		t.Fatalf("expected four exact VTB endpoints, found %d", len(ru.Domain))
	}
	for _, d := range ru.Domain {
		if d.Type != router.Domain_Full {
			t.Fatalf("unexpected suffix expansion for %s", d.Value)
		}
	}
}

func TestVTBExternalGatewayHostsRemainExact(t *testing.T) {
	category := &router.GeoSite{CountryCode: "RU"}
	seen := make(map[string]bool)
	values := []string{
		"prod.ntprog.com", "uat.ntprog.com",
		"msk-prod-gate.ntprog.com", "muat-gate.ntprog.com",
		"other-company.com",
	}
	stats := appendDomainStrings(category, values, seen, "exact-host-policy")
	if stats.written != 5 {
		t.Fatalf("expected five positive rules, got %d", stats.written)
	}
	exactCount, suffixCount := 0, 0
	for _, d := range category.Domain {
		if exactRUPositiveHosts[d.Value] {
			if d.Type != router.Domain_Full {
				t.Fatalf("%s must remain Full, got %v", d.Value, d.Type)
			}
			exactCount++
		} else if d.Type == router.Domain_RootDomain {
			suffixCount++
		}
	}
	if exactCount != 4 || suffixCount != 1 {
		t.Fatalf("unexpected exact/suffix counts: %d/%d", exactCount, suffixCount)
	}
}

func TestUnicodeBelKazAndAceFamilyTLDsCollapse(t *testing.T) {
	for _, domain := range []string{
		"пример.бел", "мысал.қаз",
		"example.xn--90ais", "example.xn--80ao21a",
	} {
		if !isRussianTLD(domain) {
			t.Fatalf("missing compact Unicode/ACE family TLD: %q", domain)
		}
	}
}

func TestGlobalTLDsAreNotCollapsed(t *testing.T) {
	cases := []string{
		"service.org",
		"service.com",
		"service.net",
		"service.io",
		"service.de",
	}

	for _, domain := range cases {
		if isRussianTLD(domain) {
			t.Fatalf("global TLD must not be treated as Russian-family TLD: %q", domain)
		}
	}
}

func TestDomainRuleKeepsClashDOMAINExactForBlock(t *testing.T) {
	typ, value, reason := parseRuleLine("DOMAIN,example.org,no-resolve")
	if reason != skipNone {
		t.Fatalf("unexpected parse reason: %v", reason)
	}
	if typ != router.Domain_Full {
		t.Fatalf("DOMAIN must be parsed as Full, got %v", typ)
	}
	if value != "example.org" {
		t.Fatalf("unexpected value: %q", value)
	}
}

func TestPositiveTextDoesNotAdmitBareOrRussianTLD(t *testing.T) {
	category := &router.GeoSite{CountryCode: "RU"}
	seen := make(map[string]bool)

	stats := appendDomainStrings(category, []string{
		"com",
		"service.ru",
		"service.рф",
		"service.org",
	}, seen, "test")

	if stats.removedBare != 1 {
		t.Fatalf("expected one bare rule removed, got %d", stats.removedBare)
	}
	if stats.removedRussian != 2 {
		t.Fatalf("expected two Russian-family rules removed, got %d", stats.removedRussian)
	}
	if stats.written != 1 {
		t.Fatalf("expected one non-Russian domain written, got %d", stats.written)
	}
	if len(category.Domain) != 1 || category.Domain[0].Value != "service.org" {
		t.Fatalf("unexpected output domains: %#v", category.Domain)
	}
}

func TestRequiredCompactRootsArePresent(t *testing.T) {
	required := map[string]bool{
		"ru":           false,
		"su":           false,
		"by":           false,
		"kz":           false,
		"xn--90ais":    false,
		"xn--80ao21a":  false,
		"xn--p1ai":     false,
		"moscow":       false,
		"xn--80adxhks": false,
		"tatar":        false,
		"xn--p1acf":    false,
		"xn--d1acj3b":  false,
		"xn--80asehdb": false,
		"xn--80aswg":   false,
		"xn--c1avg":    false,
		"xn--j1aef":    false,
		"yandex":       false,
		"sber":         false,
	}
	for _, root := range compactRussianTLDRoots {
		required[root] = true
	}
	for _, root := range compactRussianServiceRoots {
		required[root] = true
	}
	for root, ok := range required {
		if !ok {
			t.Fatalf("required compact root missing from configuration: %s", root)
		}
	}
}

func TestCompactRootsAreCanonicalACE(t *testing.T) {
	for _, root := range compactRussianTLDRoots {
		if !isValidDomain(root) {
			t.Fatalf("configured compact TLD root is not valid: %q", root)
		}
		if !isCompactRussianRoot(root) {
			t.Fatalf("TLD root not recognized as compact root: %q", root)
		}
	}
	for _, root := range compactRussianServiceRoots {
		if !isValidDomain(root) {
			t.Fatalf("configured compact service root is not valid: %q", root)
		}
		if !isCompactRussianRoot(root) || !isCompactRussianServiceRoot(root) {
			t.Fatalf("service root not recognized as compact root: %q", root)
		}
	}
}

func TestUpstreamRootCannotAbsorbAnyApprovedExactHost(t *testing.T) {
	for host := range exactRUPositiveHosts {
		for _, first := range []bool{true, false} {
			ru := &router.GeoSite{CountryCode: "RU"}
			seen := make(map[string]bool)
			addAncestors := func() {
				for root := host; ; {
					if addRoot(ru, seen, root) {
						t.Fatalf("RootDomain %q would widen Full %q", root, host)
					}
					dot := strings.IndexByte(root, '.')
					if dot < 0 {
						break
					}
					root = root[dot+1:]
				}
			}
			if first {
				addAncestors()
			}
			if !addPositiveRule(ru, seen, host) {
				t.Fatalf("Full %q was not added", host)
			}
			if !first {
				addAncestors()
			}
			rules, removed := pruneCoveredDomains(ru.Domain)
			if removed != 0 || len(rules) != 1 || rules[0].Type != router.Domain_Full {
				t.Fatalf("Full %q was pruned or widened", host)
			}
		}
	}
}

func TestSuppressionIsLabelBoundedAndRUOnly(t *testing.T) {
	for _, input := range []struct{ category, host string }{
		{"RU", "notaltlinux.org"},
		{"RU", "foo.ftp.altlinux.org"},
		{"BLOCK", "altlinux.org"},
	} {
		site := &router.GeoSite{CountryCode: input.category}
		if !addRoot(site, make(map[string]bool), input.host) {
			t.Fatalf("unexpected suppression in %s: %s", input.category, input.host)
		}
	}
	path := filepath.Join(t.TempDir(), "report.tsv")
	if addRoot(&router.GeoSite{CountryCode: "RU"}, make(map[string]bool), "altlinux.org") {
		t.Fatal("unapproved parent was added")
	}
	if err := writeSuppressedExactAncestors(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "altlinux.org\tdocs.altlinux.org,ftp.altlinux.org,packages.altlinux.org\n") {
		t.Fatalf("missing deterministic suppression evidence: %q (%v)", data, err)
	}
}
