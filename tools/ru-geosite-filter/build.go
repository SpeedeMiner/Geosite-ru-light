package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	router "github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

const (
	argRunetfreedom = iota
	argHydra
	argGrimbird
	argMvrvntn
	argYularzhi
	argVpnyasha
	argKirill
	argDigne
	argDavoyan
	argManifest
	argHydraAppend
	argLocalRU
	argLocalBlock
	argW1zardz
	argKyoresuas
	argReport
	argOutput
	buildArgCount
)

const buildUsage = "usage: %s build runetfreedom.dat hydra.dat grimbird.dat mvrvntn.dat yularzhi.dat vpnyasha.dat kirill.dat digne.dat davoyan-legacy.txt selected.txt hydra_append.txt local-ru.txt local-block.txt w1zardz-ru-direct.txt kyoresuas-ru-standard-domains.txt new-positive-report.txt output.dat\n"

const defaultMinRURules = 800

func minRURules() int {
	value := strings.TrimSpace(os.Getenv("MIN_RU_RULES"))
	if value == "" {
		return defaultMinRURules
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		fatalf("invalid MIN_RU_RULES value: %q", value)
	}
	return n
}

// A positive source may contain foreign streaming endpoints. They must
// not be promoted into geosite:RU merely because a third-party list
// once marked them DIRECT. Keep this denial narrowly scoped to RU.
var excludedRUPositiveDomains = map[string]bool{
	"stream.kick.com": true, // Kick international video stream CDN
}

// The user explicitly forbids any DIRECT coverage of 4pda.to,
// including its subdomains. Check both descendants and a RootDomain
// ancestor (e.g. a future "to" root) that would cover 4pda.to.
func forbidden4PDAInRU(typ router.Domain_Type, value string) bool {
	const apex = "4pda.to"
	name := normalizeName(value)
	if name == apex || strings.HasSuffix(name, "."+apex) {
		return true
	}
	return typ == router.Domain_RootDomain && strings.HasSuffix(apex, "."+name)
}

func addRoot(site *router.GeoSite, seen map[string]bool, value string) bool {
	if normalizeName(site.CountryCode) == "ru" &&
		(excludedRUPositiveDomains[normalizeName(value)] ||
			forbidden4PDAInRU(router.Domain_RootDomain, value)) {
		return false
	}
	if normalizeName(site.CountryCode) == "ru" {
		value = normalizeName(value)
		if hosts := approvedExactByAncestor[value]; len(hosts) > 0 {
			suppressedExactAncestors[value] = hosts
			return false
		}
	}
	key := domainValueKey(router.Domain_RootDomain, value)
	if seen[key] {
		return false
	}
	seen[key] = true
	site.Domain = append(site.Domain, &router.Domain{
		Type:  router.Domain_RootDomain,
		Value: value,
	})
	return true
}

func pruneCoveredDomains(domains []*router.Domain) ([]*router.Domain, int) {
	roots := make(map[string]bool)
	for _, domain := range domains {
		if domain == nil || domain.Type != router.Domain_RootDomain {
			continue
		}
		if value := normalizeName(domain.Value); value != "" {
			roots[value] = true
		}
	}

	result := make([]*router.Domain, 0, len(domains))
	removed := 0
	for _, domain := range domains {
		if domain == nil {
			continue
		}

		value := normalizeName(domain.Value)
		covered := false
		switch domain.Type {
		case router.Domain_RootDomain:
			covered = hasRootAncestor(value, roots)
		case router.Domain_Full:
			covered = isCoveredByRoots(value, roots)
		}

		if covered {
			removed++
			continue
		}
		result = append(result, domain)
	}
	return result, removed
}

func sortDomains(domains []*router.Domain) {
	sort.Slice(domains, func(i, j int) bool {
		a, b := domains[i], domains[j]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return normalizeName(a.Value) < normalizeName(b.Value)
	})
}

type appendDomainStats struct {
	written            int
	duplicates         int
	removedRussian     int
	removedServiceRoot int
	removedBare        int
	removedInvalid     int
}

// Exact hosts are explicit approval policy, not source-list inference.
// Use the same manifest as the production semantic delta gate.
var exactRUPositiveHosts map[string]bool
var approvedExactByAncestor map[string][]string
var suppressedExactAncestors = make(map[string][]string)

func indexExactAncestors(exact map[string]bool) map[string][]string {
	index := make(map[string][]string)
	for host := range exact {
		for root := host; ; {
			index[root] = append(index[root], host)
			dot := strings.IndexByte(root, '.')
			if dot < 0 {
				break
			}
			root = root[dot+1:]
		}
	}
	for _, hosts := range index {
		sort.Strings(hosts)
	}
	return index
}

func loadExactRUPositiveHosts(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	exact := make(map[string]bool)
	roots := make(map[string]bool)
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kind, value, ok := strings.Cut(line, ":")
		if !ok || (kind != "domain" && kind != "full") ||
			value != normalizeName(value) || !isValidDomain(value) {
			return nil, fmt.Errorf("invalid approved RU rule on line %d: %q", i+1, line)
		}
		if kind == "domain" {
			if roots[value] {
				return nil, fmt.Errorf("duplicate approved root on line %d: %q", i+1, line)
			}
			roots[value] = true
			continue
		}
		if !strings.Contains(value, ".") || isRussianTLD(value) ||
			forbidden4PDAInRU(router.Domain_Full, value) || exact[value] {
			return nil, fmt.Errorf("invalid or duplicate Full rule on line %d: %q", i+1, line)
		}
		exact[value] = true
	}
	if len(exact) == 0 {
		return nil, fmt.Errorf("approved manifest has no Full rules")
	}
	index := indexExactAncestors(exact)
	for root := range roots {
		if hosts := index[root]; len(hosts) > 0 {
			return nil, fmt.Errorf("approved RootDomain %q would absorb Full hosts %v; explicitly replace those Full approvals when widening scope", root, hosts)
		}
	}
	return exact, nil
}

func writeSuppressedExactAncestors(path string) error {
	var report strings.Builder
	fmt.Fprintln(&report, "suppressed_root\tprotected_exact_hosts")
	roots := make([]string, 0, len(suppressedExactAncestors))
	for root := range suppressedExactAncestors {
		roots = append(roots, root)
	}
	sort.Strings(roots)
	for _, root := range roots {
		hosts := strings.Join(suppressedExactAncestors[root], ",")
		fmt.Printf("NOTE: skipped unapproved RU parent root %s covering exact hosts %s\n", root, hosts)
		fmt.Fprintf(&report, "%s\t%s\n", root, hosts)
	}
	if path == "" {
		return nil
	}
	return os.WriteFile(path, []byte(report.String()), 0644)
}

func addPositiveRule(category *router.GeoSite, seen map[string]bool, value string) bool {
	if normalizeName(category.CountryCode) == "ru" &&
		forbidden4PDAInRU(router.Domain_Full, value) {
		return false
	}
	if normalizeName(category.CountryCode) == "ru" && exactRUPositiveHosts[value] {
		key := domainValueKey(router.Domain_Full, value)
		if seen[key] {
			return false
		}
		seen[key] = true
		category.Domain = append(category.Domain, &router.Domain{Type: router.Domain_Full, Value: value})
		return true
	}
	return addRoot(category, seen, value)
}

func appendDomainStrings(category *router.GeoSite, values []string, seen map[string]bool, label string) appendDomainStats {
	stats := appendDomainStats{}
	for _, value := range values {
		value = normalizeName(value)
		if value == "" {
			continue
		}
		if isRussianTLD(value) {
			stats.removedRussian++
			continue
		}
		if isCoveredByCompactServiceRoot(value) {
			stats.removedServiceRoot++
			continue
		}
		if !strings.Contains(value, ".") {
			stats.removedBare++
			continue
		}
		if !isValidDomain(value) {
			stats.removedInvalid++
			continue
		}
		if !addPositiveRule(category, seen, value) {
			stats.duplicates++
			continue
		}
		stats.written++
	}

	if stats.removedServiceRoot > 0 {
		fmt.Printf("NOTE: %s: removed domains covered by compact service roots: %d\n", label, stats.removedServiceRoot)
	}
	if stats.removedBare > 0 {
		fmt.Printf("NOTE: %s: removed bare single-label rules: %d\n", label, stats.removedBare)
	}
	if stats.removedInvalid > 0 {
		fmt.Printf("NOTE: %s: removed invalid domain rules: %d\n", label, stats.removedInvalid)
	}
	return stats
}

func collectNewPositiveSource(path, label string, baseRoots map[string]bool) (values []string, sourceLines int, skippedRussianTLD int, skippedServiceRoot int, skippedBare int, skippedInvalid int, err error) {
	sourceValues, err := loadDomainList(path, true, label)
	if err != nil {
		return nil, 0, 0, 0, 0, 0, err
	}

	sort.Slice(sourceValues, func(i, j int) bool {
		di := strings.Count(sourceValues[i], ".")
		dj := strings.Count(sourceValues[j], ".")
		if di != dj {
			return di < dj
		}
		return sourceValues[i] < sourceValues[j]
	})

	for _, value := range sourceValues {
		sourceLines++
		if isRussianTLD(value) {
			skippedRussianTLD++
			continue
		}
		if isCoveredByCompactServiceRoot(value) {
			skippedServiceRoot++
			continue
		}
		if !strings.Contains(value, ".") {
			skippedBare++
			continue
		}
		if !isValidDomain(value) {
			skippedInvalid++
			continue
		}
		if isCoveredByRoots(value, baseRoots) {
			continue
		}
		values = append(values, value)
	}
	return values, sourceLines, skippedRussianTLD, skippedServiceRoot, skippedBare, skippedInvalid, nil
}

func runBuild(args []string) {
	if len(args) != buildArgCount {
		fmt.Fprintf(os.Stderr, buildUsage, os.Args[0])
		os.Exit(2)
	}

	outputPath := args[argOutput]
	reportPath := args[argReport]

	if outputPath == reportPath {
		fatalf("output path and report path are the same: %s", outputPath)
	}
	for i := 0; i < argReport; i++ {
		if args[i] == outputPath {
			fatalf("output path collides with input argument %d: %s", i+1, outputPath)
		}
		if args[i] == reportPath {
			fatalf("report path collides with input argument %d: %s", i+1, reportPath)
		}
	}

	sources := []struct{ name, path string }{
		{"runetfreedom", args[argRunetfreedom]},
		{"hydra", args[argHydra]},
		{"grimbird", args[argGrimbird]},
		{"mvrvntn", args[argMvrvntn]},
		{"yularzhi", args[argYularzhi]},
		{"vpnyasha", args[argVpnyasha]},
		{"kirill", args[argKirill]},
		{"digne", args[argDigne]},
	}

	fmt.Println("Text sources:")
	legacyDomains, err := loadDomainList(args[argDavoyan], true, "Davoyan legacy")
	if err != nil {
		fatalf("failed to read Davoyan legacy list: %v", err)
	}
	localRUDomains, err := loadDomainList(args[argLocalRU], false, "local RU")
	if err != nil {
		fatalf("failed to read local RU list: %v", err)
	}
	localBlockDomains, err := loadBlockDomainList(args[argLocalBlock], "local BLOCK")
	if err != nil {
		fatalf("failed to read local BLOCK list: %v", err)
	}

	positiveExtras := []struct{ name, path string }{
		{"w1zardz-ru-direct-domains", args[argW1zardz]},
		{"kyoresuas-ru-standard", args[argKyoresuas]},
	}

	manifest, err := loadManifest(args[argManifest])
	if err != nil {
		fatalf("failed to read manifest: %v", err)
	}

	lists := make(map[string]*router.GeoSiteList, len(sources))
	for _, source := range sources {
		list, err := loadGeoSite(source.path)
		if err != nil {
			fatalf("%v", err)
		}
		lists[source.name] = list
	}

	result := new(router.GeoSiteList)
	ruCategory := &router.GeoSite{CountryCode: "RU"}
	blockCategory := &router.GeoSite{CountryCode: "BLOCK"}
	globalSeen := make(map[string]bool)

	var (
		sourceCategoryCount, sourceDomainCount, writtenDomainCount     int
		duplicateDomainCount, removedRussianDomainCount                int
		removedServiceRootDomainCount                                  int
		removedUnsupportedTypeCount, convertedFullToRootCount          int
		removedCoveredDomainCount                                      int
		localBlockDomainCount, removedCoveredBlockDomainCount          int
		sourceAttributeCount, hydraAttributeCount                      int
		appendedRuleCount, appendedDuplicateCount                      int
		appendedConvertedFullToRootCount, appendedUnsupportedTypeCount int
		appendedCoveredDomainCount                                     int
		removedBareDomainCount, removedInvalidDomainCount              int
		totalPositiveInput, totalPositiveNew, totalPositiveAdded       int
		totalPositiveTLD, totalPositiveBare, totalPositiveInvalid      int
		totalPositiveServiceRoot                                       int
		compactTLDRootsAdded, compactServiceRootsAdded                 int
	)

	manifestSources := make([]string, 0, len(manifest))
	for source := range manifest {
		manifestSources = append(manifestSources, source)
	}
	sort.Strings(manifestSources)

	matched := make(map[string]map[string]bool, len(sources))
	for _, source := range sources {
		matched[source.name] = make(map[string]bool)
	}

	for _, source := range manifestSources {
		list, ok := lists[source]
		if !ok {
			fatalf("unknown source in manifest: %s", source)
		}
		selectedCategories := manifest[source]

		for _, site := range list.Entry {
			if site == nil {
				continue
			}

			category := normalizeName(site.CountryCode)
			if !selectedCategories[category] {
				continue
			}

			matched[source][category] = true
			sourceCategoryCount++

			for _, domain := range site.Domain {
				if domain == nil {
					continue
				}

				sourceDomainCount++
				sourceAttributeCount += len(domain.Attribute)

				switch domain.Type {
				case router.Domain_RootDomain:
				case router.Domain_Full:
					convertedFullToRootCount++
				default:
					removedUnsupportedTypeCount++
					continue
				}

				value := normalizeName(domain.Value)
				if value == "" {
					continue
				}
				if hasAttributeMarker(value) {
					fatalf("attribute marker embedded in RU source domain value: %s", domain.Value)
				}
				if isRussianTLD(value) {
					removedRussianDomainCount++
					continue
				}
				if isCoveredByCompactServiceRoot(value) {
					removedServiceRootDomainCount++
					continue
				}
				if !strings.Contains(value, ".") {
					removedBareDomainCount++
					continue
				}
				if !isValidDomain(value) {
					removedInvalidDomainCount++
					continue
				}

				if !addPositiveRule(ruCategory, globalSeen, value) {
					duplicateDomainCount++
					continue
				}
				writtenDomainCount++
			}
		}
	}

	var missingExternal []string
	for _, source := range sources[1:] {
		for category := range manifest[source.name] {
			if !matched[source.name][category] {
				missingExternal = append(missingExternal, source.name+"|"+category)
			}
		}
	}
	if len(missingExternal) > 0 {
		sort.Strings(missingExternal)
		fatalf("required external categories missing from source DATs: %s", strings.Join(missingExternal, ", "))
	}

	if !matched["runetfreedom"]["category-ru"] {
		fatalf("category-ru not found in the runetfreedom DAT")
	}
	var absent []string
	for category := range manifest["runetfreedom"] {
		if !matched["runetfreedom"][category] {
			absent = append(absent, category)
		}
	}
	if len(absent) > 0 {
		sort.Strings(absent)
		fmt.Printf("NOTE: %d v2fly categories are absent from the runetfreedom DAT (ignored): %s\n", len(absent), strings.Join(absent, ", "))
	}

	legacyDomainCount := len(legacyDomains)
	legacyStats := appendDomainStrings(ruCategory, legacyDomains, globalSeen, "Davoyan legacy")
	writtenDomainCount += legacyStats.written
	duplicateDomainCount += legacyStats.duplicates
	removedRussianDomainCount += legacyStats.removedRussian
	removedServiceRootDomainCount += legacyStats.removedServiceRoot
	removedBareDomainCount += legacyStats.removedBare
	removedInvalidDomainCount += legacyStats.removedInvalid

	localStats := appendDomainStrings(ruCategory, localRUDomains, globalSeen, "local RU")
	writtenDomainCount += localStats.written
	duplicateDomainCount += localStats.duplicates
	removedRussianDomainCount += localStats.removedRussian
	removedServiceRootDomainCount += localStats.removedServiceRoot
	removedBareDomainCount += localStats.removedBare
	removedInvalidDomainCount += localStats.removedInvalid

	blockSeen := make(map[string]bool)
	localBlockDuplicateCount := 0
	for _, domain := range localBlockDomains {
		key := domainKey(domain)
		if blockSeen[key] {
			localBlockDuplicateCount++
			continue
		}
		blockSeen[key] = true
		blockCategory.Domain = append(blockCategory.Domain, domain)
		localBlockDomainCount++
	}

	// Compact every configured RU-family TLD, then every explicitly
	// configured Russian service root. Both are represented by one
	// RootDomain rule so thousands of concrete child names collapse.
	for _, value := range compactRussianTLDRoots {
		if addRoot(ruCategory, globalSeen, value) {
			writtenDomainCount++
			compactTLDRootsAdded++
		}
	}
	for _, value := range compactRussianServiceRoots {
		if addRoot(ruCategory, globalSeen, value) {
			writtenDomainCount++
			compactServiceRootsAdded++
		}
	}

	reportFile, err := os.Create(reportPath)
	if err != nil {
		fatalf("failed to create positive-source report: %v", err)
	}
	report := bufio.NewWriter(reportFile)

	fmt.Fprintln(report, "# Positive-only RU source delta")
	fmt.Fprintln(report, "# NEW = source domain not covered by the pre-enrichment RU root-domain set")
	fmt.Fprintln(report, "# refilter/block/negative feeds are intentionally excluded")
	fmt.Fprintln(report, "# Russian-family TLDs and configured service roots are compacted to RootDomain roots")
	fmt.Fprintln(report)

	baseRoots := make(map[string]bool)
	for _, domain := range ruCategory.Domain {
		if domain.Type == router.Domain_RootDomain {
			baseRoots[normalizeName(domain.Value)] = true
		}
	}

	finalRoots := make(map[string]bool, len(baseRoots))
	for root := range baseRoots {
		finalRoots[root] = true
	}

	for _, extra := range positiveExtras {
		values, sourceLines, skippedTLD, skippedService, skippedBare, skippedInvalid, err := collectNewPositiveSource(extra.path, extra.name, baseRoots)
		if err != nil {
			fatalf("failed positive source %s: %v", extra.name, err)
		}

		fmt.Fprintf(report, "\n[%s]\n", extra.name)
		addedCount := 0

		for _, value := range values {
			fmt.Fprintln(report, value)

			if isCoveredByRoots(value, finalRoots) {
				continue
			}
			if !addPositiveRule(ruCategory, globalSeen, value) {
				continue
			}
			// Full vendor endpoints must not behave as broad suffix
			// roots in the positive-sources deduplication index.
			if !exactRUPositiveHosts[value] {
				finalRoots[value] = true
			}
			writtenDomainCount++
			addedCount++
		}

		totalPositiveInput += sourceLines
		totalPositiveNew += len(values)
		totalPositiveAdded += addedCount
		totalPositiveTLD += skippedTLD
		totalPositiveServiceRoot += skippedService
		totalPositiveBare += skippedBare
		totalPositiveInvalid += skippedInvalid
		fmt.Fprintf(report, "# source_lines=%d new_vs_base=%d added_to_final_before_prune=%d skipped_ru_tld=%d skipped_service_root=%d skipped_bare=%d skipped_invalid=%d\n", sourceLines, len(values), addedCount, skippedTLD, skippedService, skippedBare, skippedInvalid)
	}

	fmt.Fprintf(report, "\nTOTAL positive source lines: %d\n", totalPositiveInput)
	fmt.Fprintf(report, "TOTAL new vs base RU: %d\n", totalPositiveNew)
	fmt.Fprintf(report, "TOTAL added to final before prune: %d\n", totalPositiveAdded)
	fmt.Fprintf(report, "TOTAL skipped RU TLD: %d\n", totalPositiveTLD)
	fmt.Fprintf(report, "TOTAL skipped compact service root: %d\n", totalPositiveServiceRoot)
	fmt.Fprintf(report, "TOTAL skipped bare: %d\n", totalPositiveBare)
	fmt.Fprintf(report, "TOTAL skipped invalid: %d\n", totalPositiveInvalid)

	if err := report.Flush(); err != nil {
		fatalf("failed to write positive-source report: %v", err)
	}
	if err := reportFile.Close(); err != nil {
		fatalf("failed to close positive-source report: %v", err)
	}

	if err := writeSuppressedExactAncestors(os.Getenv("RU_SUPPRESSED_ROOTS_REPORT")); err != nil {
		fatalf("failed to write suppressed root report: %v", err)
	}

	var pruned int
	ruCategory.Domain, pruned = pruneCoveredDomains(ruCategory.Domain)
	removedCoveredDomainCount += pruned
	// Required even in scheduled main builds, where PR-only delta
	// checks do not run. Never emit forbidden DIRECT coverage.
	for _, domain := range ruCategory.Domain {
		if forbidden4PDAInRU(domain.Type, domain.Value) {
			fatalf("4pda.to no-DIRECT production policy violated: %v:%s", domain.Type, domain.Value)
		}
	}
	sortDomains(ruCategory.Domain)

	blockCategory.Domain, removedCoveredBlockDomainCount = pruneCoveredDomains(blockCategory.Domain)
	sortDomains(blockCategory.Domain)

	if floor := minRURules(); len(ruCategory.Domain) < floor {
		fatalf("RU category has only %d rules (minimum %d): upstream sources look broken", len(ruCategory.Domain), floor)
	}

	result.Entry = append(result.Entry, ruCategory, blockCategory)

	hydraAppendCategories, err := loadOrderedCategories(args[argHydraAppend])
	if err != nil {
		fatalf("failed to read Hydra append manifest: %v", err)
	}

	wanted := make(map[string]bool, len(hydraAppendCategories))
	for _, category := range hydraAppendCategories {
		wanted[category] = true
	}

	hydraByCategory := make(map[string]*router.GeoSite)
	for _, site := range lists["hydra"].Entry {
		if site == nil {
			continue
		}
		category := normalizeName(site.CountryCode)
		if !wanted[category] {
			continue
		}
		if _, exists := hydraByCategory[category]; exists {
			fatalf("duplicate source category in Hydra DAT: %s", category)
		}
		hydraByCategory[category] = site
	}

	for _, category := range hydraAppendCategories {
		site, ok := hydraByCategory[category]
		if !ok {
			fatalf("required Hydra category missing: %s", category)
		}

		dst := &router.GeoSite{CountryCode: strings.ToUpper(category)}
		seen := make(map[string]bool, len(site.Domain))

		for _, domain := range site.Domain {
			if domain == nil {
				continue
			}

			hydraAttributeCount += len(domain.Attribute)
			value := normalizeName(domain.Value)
			if value == "" {
				continue
			}
			if hasAttributeMarker(value) {
				fatalf("attribute marker embedded in Hydra source domain value: %s", domain.Value)
			}

			switch domain.Type {
			case router.Domain_RootDomain:
			case router.Domain_Full:
				appendedConvertedFullToRootCount++
			default:
				appendedUnsupportedTypeCount++
				continue
			}

			if !isValidDomain(value) {
				fatalf("invalid domain in Hydra category %s: %s", category, domain.Value)
			}

			if !addRoot(dst, seen, value) {
				appendedDuplicateCount++
				continue
			}
			appendedRuleCount++
		}

		var prunedHydra int
		dst.Domain, prunedHydra = pruneCoveredDomains(dst.Domain)
		appendedCoveredDomainCount += prunedHydra
		sortDomains(dst.Domain)

		if len(dst.Domain) == 0 {
			fatalf("Hydra category is empty: %s", category)
		}
		result.Entry = append(result.Entry, dst)
	}

	outputData, err := proto.MarshalOptions{Deterministic: true}.Marshal(result)
	if err != nil {
		fatalf("failed to marshal final output DAT: %v", err)
	}
	if err := os.WriteFile(outputPath, outputData, 0o644); err != nil {
		fatalf("failed to write output DAT: %v", err)
	}

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("RU LIGHT GEOSITE BUILD v10")
	fmt.Println("========================================")
	fmt.Printf("Source category matches       : %d\n", sourceCategoryCount)
	fmt.Printf("Source domain rules           : %d\n", sourceDomainCount)
	fmt.Printf("Written domain rules          : %d (before pruning)\n", writtenDomainCount)
	fmt.Printf("Removed configured RU TLD     : %d\n", removedRussianDomainCount)
	fmt.Printf("Removed compact service domains : %d\n", removedServiceRootDomainCount)
	fmt.Printf("Removed bare single-label     : %d\n", removedBareDomainCount)
	fmt.Printf("Removed invalid domains      : %d\n", removedInvalidDomainCount)
	fmt.Printf("Removed regex/keyword        : %d\n", removedUnsupportedTypeCount)
	fmt.Printf("Removed duplicates             : %d\n", duplicateDomainCount)
	fmt.Printf("Full -> RootDomain (RU)       : %d\n", convertedFullToRootCount)
	fmt.Printf("Covered RU domains removed    : %d\n", removedCoveredDomainCount)
	fmt.Printf("Davoyan legacy domains        : %d\n", legacyDomainCount)
	fmt.Printf("Davoyan legacy written        : %d\n", legacyStats.written)
	fmt.Printf("Local RU written              : %d\n", localStats.written)
	fmt.Printf("Local BLOCK domains           : %d\n", localBlockDomainCount)
	fmt.Printf("Local BLOCK duplicates        : %d\n", localBlockDuplicateCount)
	fmt.Printf("Covered BLOCK domains removed : %d\n", removedCoveredBlockDomainCount)
	fmt.Printf("Compact RU TLD roots added    : %d/%d\n", compactTLDRootsAdded, len(compactRussianTLDRoots))
	fmt.Printf("Compact service roots added    : %d/%d\n", compactServiceRootsAdded, len(compactRussianServiceRoots))
	fmt.Printf("Appended Hydra rules          : %d\n", appendedRuleCount)
	fmt.Printf("Hydra duplicates removed     : %d\n", appendedDuplicateCount)
	fmt.Printf("Full -> RootDomain (Hydra)    : %d\n", appendedConvertedFullToRootCount)
	fmt.Printf("Removed unsupported Hydra     : %d\n", appendedUnsupportedTypeCount)
	fmt.Printf("Covered Hydra domains removed : %d\n", appendedCoveredDomainCount)
	fmt.Printf("Source attributes encountered : %d\n", sourceAttributeCount)
	fmt.Printf("Hydra attributes encountered  : %d\n", hydraAttributeCount)
	fmt.Printf("Positive source lines         : %d\n", totalPositiveInput)
	fmt.Printf("Positive NEW vs base RU      : %d\n", totalPositiveNew)
	fmt.Printf("Positive added to final      : %d\n", totalPositiveAdded)
	fmt.Printf("Positive skipped RU TLD       : %d\n", totalPositiveTLD)
	fmt.Printf("Positive skipped service root : %d\n", totalPositiveServiceRoot)
	fmt.Printf("Positive skipped bare         : %d\n", totalPositiveBare)
	fmt.Printf("Positive skipped invalid      : %d\n", totalPositiveInvalid)
	fmt.Printf("Positive delta report         : %s\n", reportPath)
	fmt.Printf("FINAL RU rules               : %d\n", len(ruCategory.Domain))
	fmt.Printf("FINAL BLOCK rules            : %d\n", len(blockCategory.Domain))
	fmt.Printf("Final categories              : %d\n", len(result.Entry))
	fmt.Printf("Final DAT size                : %d bytes\n", len(outputData))
	fmt.Printf("Output categories             : RU + BLOCK + %d Hydra categories (clean attributes)\n", len(hydraAppendCategories))
	fmt.Println()
	fmt.Println("Configured compact RU-family TLD roots:")
	for _, root := range compactRussianTLDRoots {
		fmt.Printf("  domain:%s\n", root)
	}
	fmt.Println("Configured compact RU service roots:")
	for _, root := range compactRussianServiceRoots {
		fmt.Printf("  domain:%s\n", root)
	}
}
