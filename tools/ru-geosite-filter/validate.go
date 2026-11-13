package main

import (
	"fmt"
	"strings"

	router "github.com/v2fly/v2ray-core/v5/app/router/routercommon"
)

func validateRules(name string, domains []*router.Domain, allowFull bool) {
	roots := make(map[string]bool, len(domains))
	for _, domain := range domains {
		if domain != nil && domain.Type == router.Domain_RootDomain {
			if value := normalizeName(domain.Value); value != "" {
				roots[value] = true
			}
		}
	}

	seen := make(map[string]bool, len(domains))
	for _, domain := range domains {
		if domain == nil {
			fatalf("%s contains nil domain", name)
		}
		if len(domain.Attribute) > 0 {
			fatalf("leaked attributes in %s domain: %s (count: %d)", name, domain.Value, len(domain.Attribute))
		}

		switch domain.Type {
		case router.Domain_RootDomain:
		case router.Domain_Full:
			if !allowFull {
				fatalf("Full rule remained in %s: %s", name, domain.Value)
			}
		default:
			fatalf("%s contains unsupported rule type %v: %s", name, domain.Type, domain.Value)
		}

		value := normalizeName(domain.Value)
		if value == "" {
			fatalf("%s contains empty domain value", name)
		}
		if hasAttributeMarker(value) {
			fatalf("attribute marker leaked into %s value: %s", name, domain.Value)
		}
		if !isValidDomain(value) {
			fatalf("invalid domain syntax in %s: %s", name, domain.Value)
		}

		key := domainKey(domain)
		if seen[key] {
			fatalf("duplicate domain in %s: %s", name, domain.Value)
		}
		seen[key] = true

		covered := false
		if domain.Type == router.Domain_RootDomain {
			covered = hasRootAncestor(value, roots)
		} else {
			covered = isCoveredByRoots(value, roots)
		}
		if covered {
			fatalf("redundant rule in %s: %s is covered by a RootDomain", name, value)
		}
	}
}

func runValidate(args []string) {
	if len(args) != 2 {
		usage()
	}

	list, err := loadGeoSite(args[0])
	if err != nil {
		fatalf("%v", err)
	}

	expectedHydra, err := loadOrderedCategories(args[1])
	if err != nil {
		fatalf("failed to read Hydra append manifest: %v", err)
	}

	wantEntries := 2 + len(expectedHydra)
	if len(list.Entry) != wantEntries {
		fatalf("expected exactly %d categories, got %d", wantEntries, len(list.Entry))
	}

	for _, site := range list.Entry {
		if site == nil {
			fatalf("output contains nil category")
		}
		category := normalizeName(site.CountryCode)
		if strings.Contains(category, "@") {
			fatalf("attribute marker leaked into category name: %s", site.CountryCode)
		}
		for _, marker := range []string{"blocked", "geoblock", "re-filter", "refilter"} {
			if strings.Contains(category, marker) {
				fatalf("negative category leaked into output: %s", site.CountryCode)
			}
		}
	}

	// ---- RU ----------------------------------------------------------------
	ru := list.Entry[0]
	if normalizeName(ru.CountryCode) != "ru" {
		fatalf("first category must be RU")
	}
	if floor := minRURules(); len(ru.Domain) < floor {
		fatalf("RU has only %d rules (minimum %d)", len(ru.Domain), floor)
	}

	// Only explicitly approved hosts may be Full in RU.
	// Validation requires their exact type even if a source changes.
	validateRules("RU", ru.Domain, true)
	for _, entry := range ru.Domain {
		if forbidden4PDAInRU(entry.Type, entry.Value) {
			fatalf("4pda.to prohibited in output RU DAT: %v:%s", entry.Type, entry.Value)
		}
	}
	exactSeen := make(map[string]bool)
	for _, entry := range ru.Domain {
		if entry.Type == router.Domain_Full {
			name := normalizeName(entry.Value)
			if !exactRUPositiveHosts[name] {
				fatalf("unapproved Full rule in RU: %s", name)
			}
			exactSeen[name] = true
		}
	}
	for name := range exactRUPositiveHosts {
		if !exactSeen[name] {
			fatalf("required approved exact host missing from RU DAT: %s", name)
		}
	}

	compactTLD := make(map[string]bool, len(compactRussianTLDRoots))
	for _, root := range compactRussianTLDRoots {
		compactTLD[root] = false
	}

	compactService := make(map[string]bool, len(compactRussianServiceRoots))
	for _, root := range compactRussianServiceRoots {
		compactService[root] = false
	}

	for _, domain := range ru.Domain {
		value := normalizeName(domain.Value)
		if isRussianTLD(value) {
			if _, ok := compactTLD[value]; !ok {
				fatalf("uncompacted Russian-family TLD leaked into RU: %s", domain.Value)
			}
			if domain.Type != router.Domain_RootDomain {
				fatalf("compact Russian-family TLD is not RootDomain: %s", domain.Value)
			}
			compactTLD[value] = true
		}
		if isCompactRussianServiceRoot(value) {
			if domain.Type != router.Domain_RootDomain {
				fatalf("compact Russian service root is not RootDomain: %s", domain.Value)
			}
			compactService[value] = true
		}
		if !strings.Contains(value, ".") && !isCompactRussianRoot(value) {
			fatalf("bare non-compact rule leaked into RU: %s", domain.Value)
		}
	}

	for root, ok := range compactTLD {
		if !ok {
			fatalf("RU missing compact TLD root: %s", root)
		}
	}
	for root, ok := range compactService {
		if !ok {
			fatalf("RU missing compact service root: %s", root)
		}
	}

	// ---- BLOCK -------------------------------------------------------------
	block := list.Entry[1]
	if normalizeName(block.CountryCode) != "block" {
		fatalf("second category must be BLOCK")
	}
	validateRules("BLOCK", block.Domain, true)

	// ---- Hydra -------------------------------------------------------------
	for i, expected := range expectedHydra {
		site := list.Entry[i+2]
		if category := normalizeName(site.CountryCode); category != expected {
			fatalf("Hydra category order mismatch: expected %s, got %s", expected, site.CountryCode)
		}
		if len(site.Domain) == 0 {
			fatalf("Hydra category is empty: %s", expected)
		}
		validateRules(expected, site.Domain, false)
	}

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("VALIDATION OK")
	fmt.Println("========================================")
	fmt.Printf("Categories: %d (RU + BLOCK + %d Hydra)\n", len(list.Entry), len(expectedHydra))
	fmt.Printf("RU rules:   %d\n", len(ru.Domain))
	fmt.Printf("BLOCK rules: %d\n", len(block.Domain))
	fmt.Printf("Compact RU-family TLD roots: %d\n", len(compactRussianTLDRoots))
	fmt.Printf("Compact RU service roots: %d\n", len(compactRussianServiceRoots))
	fmt.Println("Attributes (@ads/@cn/etc.): 0 in output")
	fmt.Println("RU policy: configured Russian-family TLDs and service roots are represented only by compact RootDomain roots")
}
