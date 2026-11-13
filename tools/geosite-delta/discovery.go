package main

// Evidence-only corporate discovery filter. It does not modify the protobuf
// GeoSite data or authorize inclusion in RU-DIRECT.
import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
)

var discoveryDomainRE = regexp.MustCompile("^[a-z0-9-]+(?:\\.[a-z0-9-]+)+$")

type discoveredDomainRow struct {
	Domain     string
	Signals    string
	Seeds      string
	Evidence   string
	IPs        string
	ASNs       string
	Groups     string
	DNSChecked string
}

func validDiscoveryDomain(domain string) bool {
	if len(domain) > 253 || !discoveryDomainRE.MatchString(domain) || net.ParseIP(domain) != nil {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}

// This only selects names eligible for bounded DNS attribution. It never
// writes rules, and previously reviewed or already routed names are skipped.
func pendingDiscoveryInventory(inventoryPath, datPath, reviewPath, outPath string) error {
	data, err := os.ReadFile(inventoryPath)
	if err != nil {
		return err
	}
	var inventory externalInventory
	if err := json.Unmarshal(data, &inventory); err != nil {
		return err
	}
	if len(inventory.Domains) == 0 {
		return fmt.Errorf("empty discovery inventory")
	}
	cats, err := decode(datPath)
	if err != nil {
		return err
	}
	ru, ok := cats["RU"]
	if !ok {
		return fmt.Errorf("candidate DAT missing RU")
	}
	block, ok := cats["BLOCK"]
	if !ok {
		return fmt.Errorf("candidate DAT missing BLOCK")
	}
	reviews, err := loadReviewDecisions(reviewPath)
	if err != nil {
		return err
	}
	unique := map[string]bool{}
	for raw := range inventory.Domains {
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		if !validDiscoveryDomain(host) || excluded4PDASubtree(host) || covered(ru, host, false) || covered(block, host, false) {
			continue
		}
		if _, reviewed := reviews[host]; reviewed {
			continue
		}
		unique[host] = true
	}
	names := make([]string, 0, len(unique))
	for host := range unique {
		names = append(names, host)
	}
	sort.Strings(names)
	var out string
	if len(names) > 0 {
		out = strings.Join(names, "\n") + "\n"
	}
	return os.WriteFile(outPath, []byte(out), 0644)
}

func readDiscoveryTSV(path string) ([]discoveredDomainRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	reader := csv.NewReader(f)
	reader.Comma = '\t'
	reader.FieldsPerRecord = 8
	all, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	expected := []string{"domain", "signals", "seeds", "evidence", "public_dns_ips", "matched_core_asns", "matched_core_groups", "dns_checked"}
	if len(all) == 0 {
		return nil, fmt.Errorf("missing discovery header")
	}
	for i, name := range expected {
		if all[0][i] != name {
			return nil, fmt.Errorf("discovery header %d: got %q expected %q", i, all[0][i], name)
		}
	}
	var result []discoveredDomainRow
	seen := map[string]bool{}
	for n, parts := range all[1:] {
		domain := strings.ToLower(strings.TrimSpace(parts[0]))
		if !validDiscoveryDomain(domain) {
			return nil, fmt.Errorf("invalid discovery domain row %d: %q", n+2, domain)
		}
		if seen[domain] {
			return nil, fmt.Errorf("duplicate discovery domain: %s", domain)
		}
		if parts[7] != "yes" && parts[7] != "no" {
			return nil, fmt.Errorf("invalid DNS status for %s", domain)
		}
		seen[domain] = true
		result = append(result, discoveredDomainRow{domain, parts[1], parts[2], parts[3], parts[4], parts[5], parts[6], parts[7]})
	}
	return result, nil
}

func safeMarkdown(s string) string {
	s = strings.ReplaceAll(s, "|", "/")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, string(rune(96)), "'")
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}

func excluded4PDASubtree(name string) bool {
	return name == "4pda.to" || strings.HasSuffix(name, ".4pda.to")
}

// Evidence priority is a review heuristic, not ownership determination.
// A single foreign CSP dependency without a CORE match or a second seed is
// weak evidence and should be reported separately, not as an RU candidate.
func strongerDiscoveryEvidence(row discoveredDomainRow) bool {
	if strings.TrimSpace(row.ASNs) != "" {
		return true
	}
	for _, signal := range strings.Split(row.Signals, ",") {
		if signal == "TLS_SAN" {
			return true
		}
	}
	groups := map[string]bool{}
	for _, seed := range strings.Split(row.Seeds, "; ") {
		if index := strings.LastIndex(seed, " ("); index >= 0 && strings.HasSuffix(seed, ")") {
			groups[seed[index+2:len(seed)-1]] = true
		}
	}
	return len(groups) >= 2
}

// otherCompiledCategoryMatches distinguishes missing RU coverage from absence
// in the entire compiled DAT. Other categories do NOT imply RU-DIRECT.
func otherCompiledCategoryMatches(rows []discoveredDomainRow, all map[string]rules) (map[string][]string, int) {
	matches := make(map[string][]string)
	found := 0
	for _, row := range rows {
		var names []string
		for cat, r := range all {
			if cat == "RU" || cat == "BLOCK" {
				continue
			}
			if covered(r, row.Domain, false) {
				names = append(names, cat)
			}
		}
		sort.Strings(names)
		matches[row.Domain] = names
		if len(names) > 0 {
			found++
		}
	}
	return matches, found
}

// writeDiscoveryReviewQueue emits only human-review work items.
// It never creates approved rules, modifies source lists or writes a DAT.
func writeDiscoveryReviewQueue(path string, priority, weak []discoveredDomainRow, other map[string][]string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	writer := csv.NewWriter(f)
	writer.Comma = '\t'
	header := []string{"domain", "review_priority", "other_dat_categories", "signals", "seeds", "evidence", "matched_core_asns", "dns_checked", "review_decision", "auto_direct"}
	if err = writer.Write(header); err != nil {
		f.Close()
		return err
	}
	for _, group := range []struct {
		rows  []discoveredDomainRow
		label string
	}{
		{priority, "PRIORITY_MANUAL_REVIEW"}, {weak, "WEAK_FOREIGN_DEPENDENCY"},
	} {
		for _, row := range group.rows {
			cats := strings.Join(other[row.Domain], ",")
			fields := []string{row.Domain, group.label, cats, row.Signals, row.Seeds, row.Evidence, row.ASNs, row.DNSChecked, "UNREVIEWED", "NO"}
			if err = writer.Write(fields); err != nil {
				f.Close()
				return err
			}
		}
	}
	writer.Flush()
	if err = writer.Error(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// filterDiscoveryCandidates compares actual protobuf RootDomain/Full coverage.
// The prior human review is independent evidence: neither an ASN match nor a
// TLS SAN/first-party CSP is sufficient to override a hold/reject.
func filterDiscoveryCandidates(rows []discoveredDomainRow, ru, block rules, reviews map[string]reviewDecision) (
	priority, weak []discoveredDomainRow, counts map[string]int) {
	counts = map[string]int{"observed": 0, "covered_RU": 0, "covered_BLOCK": 0,
		"review_hold": 0, "review_reject": 0, "4pda_excluded": 0, "new": 0,
		"priority_review": 0, "weak_external_dependencies": 0}
	for _, row := range rows {
		counts["observed"]++
		if excluded4PDASubtree(row.Domain) {
			counts["4pda_excluded"]++
			continue
		}
		if covered(ru, row.Domain, false) {
			counts["covered_RU"]++
			continue
		}
		if covered(block, row.Domain, false) {
			counts["covered_BLOCK"]++
			continue
		}
		if review, ok := reviews[row.Domain]; ok {
			switch review.status {
			case "reject":
				counts["review_reject"]++
				continue
			case "hold":
				counts["review_hold"]++
				continue
			}
		}
		counts["new"]++
		if strongerDiscoveryEvidence(row) {
			counts["priority_review"]++
			priority = append(priority, row)
		} else {
			counts["weak_external_dependencies"]++
			weak = append(weak, row)
		}
	}
	sort.Slice(priority, func(i, j int) bool { return priority[i].Domain < priority[j].Domain })
	sort.Slice(weak, func(i, j int) bool { return weak[i].Domain < weak[j].Domain })
	return priority, weak, counts
}

func discoveryReport(rawPath, datPath, reviewPath, outPath string, queuePath ...string) error {
	rows, err := readDiscoveryTSV(rawPath)
	if err != nil {
		return err
	}
	categories, err := decode(datPath)
	if err != nil {
		return err
	}
	if _, ok := categories["RU"]; !ok {
		return fmt.Errorf("candidate DAT missing RU")
	}
	if _, ok := categories["BLOCK"]; !ok {
		return fmt.Errorf("candidate DAT missing BLOCK")
	}
	reviews, err := loadReviewDecisions(reviewPath)
	if err != nil {
		return err
	}
	priority, weak, counts := filterDiscoveryCandidates(rows, categories["RU"], categories["BLOCK"], reviews)
	candidates := append(append([]discoveredDomainRow{}, priority...), weak...)
	other, otherCount := otherCompiledCategoryMatches(candidates, categories)
	if len(queuePath) > 1 {
		return fmt.Errorf("only one optional review queue path allowed")
	}
	if len(queuePath) == 1 {
		if err := writeDiscoveryReviewQueue(queuePath[0], priority, weak, other); err != nil {
			return err
		}
	}
	var b strings.Builder
	fmt.Fprintln(&b, "# Corporate-domain discovery: prioritized manual research")
	fmt.Fprintln(&b, "")
	fmt.Fprintln(&b, "**Audit-only. No domains are automatically imported into DIRECT or BLOCK.**")
	fmt.Fprintln(&b, "TLS SAN, CSP and CORE_CORPORATE ASN signals are corroborating evidence,")
	fmt.Fprintln(&b, "not legal ownership. CSP may explicitly list unrelated foreign vendors.")
	fmt.Fprintln(&b, "Wildcards are excluded; no wildcard is widened into RootDomain.")
	fmt.Fprintln(&b, "")
	fmt.Fprintf(&b, "Observed: **%d**; already RU: **%d**; BLOCK overlap: **%d**; 4PDA excluded: **%d**; existing hold/reject: **%d/%d**.\n",
		counts["observed"], counts["covered_RU"], counts["covered_BLOCK"], counts["4pda_excluded"],
		counts["review_hold"], counts["review_reject"])
	fmt.Fprintf(&b, "Uncovered and unreviewed: **%d**; prioritized for ownership verification: **%d**; low-evidence external dependencies: **%d**.\n",
		counts["new"], counts["priority_review"], counts["weak_external_dependencies"])
	fmt.Fprintln(&b, "")
	fmt.Fprintf(&b, "Among domains outside RU, **%d** are covered by other compiled DAT categories; **%d** have no exact or suffix coverage in any compiled category. These are different from the RU routing category.\n",
		otherCount, counts["new"]-otherCount)
	fmt.Fprintln(&b, "")
	fmt.Fprintln(&b, "## Cross-category coverage of uncovered RU candidates")
	fmt.Fprintln(&b, "Other-category coverage does **not** make a domain eligible for RU-DIRECT.")
	fmt.Fprintln(&b, "| Domain | Other compiled DAT categories | Review priority |")
	fmt.Fprintln(&b, "|---|---|---|")
	if len(candidates) == 0 {
		fmt.Fprintln(&b, "| — | None | — |")
	}
	for _, row := range candidates {
		label := "weak: external dependency"
		if strongerDiscoveryEvidence(row) {
			label = "manual ownership review"
		}
		cats := "none"
		if len(other[row.Domain]) > 0 {
			cats = strings.Join(other[row.Domain], ", ")
		}
		fmt.Fprintf(&b, "| %c%s%c | %s | %s |\n", 96, row.Domain, 96, safeMarkdown(cats), label)
	}
	fmt.Fprintln(&b, "")
	fmt.Fprintln(&b, "## Prioritized candidates (still require ownership verification)")
	fmt.Fprintln(&b, "CORE hosting, exact TLS SAN, or appearance on seed pages from multiple corporate groups.")
	fmt.Fprintln(&b, "| Domain | Signals | Corporate seed and evidence | CORE ASN and group (hosting signal only) | Public DNS IPs | DNS checked |")
	fmt.Fprintln(&b, "|---|---|---|---|---|---|")
	if len(priority) == 0 {
		fmt.Fprintln(&b, "| — | No prioritized uncovered candidates | — | — | — | — |")
	}
	for _, r := range priority {
		host := safeMarkdown(r.Seeds + " — " + r.Evidence)
		asns := safeMarkdown(r.ASNs + " " + r.Groups)
		fmt.Fprintf(&b, "| %c%s%c | %s | %s | %s | %s | %s |\n",
			96, r.Domain, 96, safeMarkdown(r.Signals), host, asns, safeMarkdown(r.IPs), r.DNSChecked)
	}
	fmt.Fprintln(&b, "")
	fmt.Fprintln(&b, "## Weak external dependencies (do not consider DIRECT without new proof)")
	fmt.Fprintln(&b, "An inventory-only entry or a website dependency without independent corroboration may be a foreign CDN,")
	fmt.Fprintln(&b, "analytics endpoint, or embedded third-party application. Keep for transparency,")
	fmt.Fprintln(&b, "but do not treat as a Russian domain discovery.")
	fmt.Fprintln(&b, "| Domain | Signals | Observed on | CORE match |")
	fmt.Fprintln(&b, "|---|---|---|---|")
	if len(weak) == 0 {
		fmt.Fprintln(&b, "| — | None | — | — |")
	}
	for _, r := range weak {
		match := "none"
		if r.ASNs != "" {
			match = safeMarkdown(r.ASNs)
		}
		fmt.Fprintf(&b, "| %c%s%c | %s | %s | %s |\n",
			96, r.Domain, 96, safeMarkdown(r.Signals), safeMarkdown(r.Seeds), match)
	}
	fmt.Fprintln(&b, "")
	fmt.Fprintln(&b, "## Next action")
	fmt.Fprintln(&b, "Verify first-party legal/domain ownership, service purpose, and minimal Full/Root scope.")
	fmt.Fprintln(&b, "Record source URL and rationale in a versioned review before any new positive rule.")
	if err := os.WriteFile(outPath, []byte(b.String()), 0644); err != nil {
		return err
	}
	fmt.Printf("CORPORATE_DISCOVERY_DAT_COVERAGE outside_ru=%d also_in_other_categories=%d absent_all_categories=%d\n",
		counts["new"], otherCount, counts["new"]-otherCount)
	fmt.Printf("CORPORATE_DISCOVERY_FILTER observed=%d uncovered=%d prioritized=%d weak=%d already_ru=%d block_overlap=%d holds=%d rejects=%d banned_4pda=%d report=%s\n",
		counts["observed"], counts["new"], counts["priority_review"], counts["weak_external_dependencies"],
		counts["covered_RU"], counts["covered_BLOCK"], counts["review_hold"],
		counts["review_reject"], counts["4pda_excluded"], outPath)
	return nil
}
