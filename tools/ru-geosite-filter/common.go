package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode"

	router "github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

const maxScanToken = 1024 * 1024

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}

func normalizeName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func hasAttributeMarker(value string) bool {
	return strings.Contains(value, "@")
}

// RU-zone compaction policy.
//
// TLD roots are the actual Russian / Russian-language top-level zones.
// Service roots are names that we deliberately compact for ecosystem
// coverage even when the label is not currently delegated as a TLD.
// All of these are serialized as RootDomain rules, i.e. domain:<root>.
//
// IMPORTANT: plain .org/.com/.net are NOT in the TLD list. They are global
// TLDs and must remain concrete service domains (example.org, sberbank.com,
// etc.) rather than becoming global roots.
var compactRussianTLDRoots = []string{
	"ru",           // .ru
	"su",           // .su
	"by",           // .by
	"kz",           // .kz
	"xn--90ais",    // .бел
	"xn--80ao21a",  // .қаз
	"xn--p1ai",     // .рф
	"moscow",       // .moscow
	"tatar",        // .tatar
	"xn--80adxhks", // .москва
	"xn--p1acf",    // .рус
	"xn--d1acj3b",  // .дети
	"xn--c1avg",    // .орг
	"xn--j1aef",    // .ком
	"xn--80aswg",   // .сайт
	"xn--80asehdb", // .онлайн
	"yandex",       // .yandex
}

// Service roots are compacted intentionally even though they are not
// currently part of the DNS root zone. This prepares the RU pool for the
// Sber ecosystem / future .sber naming without treating "sber" as a TLD.
var compactRussianServiceRoots = []string{
	"sber", // service root / future .sber coverage
}

var russianTLDLabels = func() map[string]bool {
	m := make(map[string]bool)

	// Canonical ACE/ASCII labels used in output.
	for _, root := range compactRussianTLDRoots {
		m[root] = true
	}

	// Unicode aliases seen in text sources.
	aliases := []string{
		"рф",
		"бел",
		"қаз",
		"москва",
		"рус",
		"дети",
		"орг",
		"ком",
		"сайт",
		"онлайн",
	}
	for _, label := range aliases {
		m[label] = true
	}

	return m
}()

// isRussianTLD reports whether value is exactly one configured RU-family
// TLD or is below one. The last-label check also handles Unicode U-labels.
// Service roots (for example sber) are deliberately excluded here.
func isRussianTLD(value string) bool {
	value = strings.TrimSuffix(strings.TrimSpace(normalizeName(value)), ".")
	if value == "" {
		return false
	}

	if dot := strings.LastIndexByte(value, '.'); dot >= 0 {
		value = value[dot+1:]
	}

	return russianTLDLabels[value]
}

func isCompactRussianRoot(value string) bool {
	value = normalizeName(value)
	for _, root := range compactRussianTLDRoots {
		if value == root {
			return true
		}
	}
	for _, root := range compactRussianServiceRoots {
		if value == root {
			return true
		}
	}
	return false
}

func isCompactRussianServiceRoot(value string) bool {
	value = normalizeName(value)
	for _, root := range compactRussianServiceRoots {
		if value == root {
			return true
		}
	}
	return false
}

// isCoveredByCompactServiceRoot reports whether value equals or is below a
// configured service root such as sber. These domains are removed from the
// concrete RU pool because the service root will be added explicitly later.
func isCoveredByCompactServiceRoot(value string) bool {
	value = normalizeName(value)
	if value == "" {
		return false
	}
	for _, root := range compactRussianServiceRoots {
		if value == root || strings.HasSuffix(value, "."+root) {
			return true
		}
	}
	return false
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func isValidDomain(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			switch {
			case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9', ch == '-', ch == '_':
			case ch > unicode.MaxASCII && (unicode.IsLetter(ch) || unicode.IsDigit(ch)):
			default:
				return false
			}
		}
	}
	return !isAllDigits(labels[len(labels)-1])
}

func domainValueKey(domainType router.Domain_Type, value string) string {
	return strconv.Itoa(int(domainType)) + "|" + normalizeName(value)
}

func domainKey(domain *router.Domain) string {
	return domainValueKey(domain.Type, domain.Value)
}

func hasRootAncestor(value string, roots map[string]bool) bool {
	for parent := value; ; {
		dot := strings.IndexByte(parent, '.')
		if dot < 0 {
			return false
		}
		parent = parent[dot+1:]
		if roots[parent] {
			return true
		}
	}
}

func isCoveredByRoots(value string, roots map[string]bool) bool {
	value = normalizeName(value)
	if value == "" {
		return false
	}
	return roots[value] || hasRootAncestor(value, roots)
}

func loadGeoSite(path string) (*router.GeoSiteList, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	list := new(router.GeoSiteList)
	if err := proto.Unmarshal(data, list); err != nil {
		return nil, fmt.Errorf("invalid geosite %s: %w", path, err)
	}
	return list, nil
}

func newScanner(file *os.File) *bufio.Scanner {
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 32*1024), maxScanToken)
	return scanner
}

func loadManifest(path string) (map[string]map[string]bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	result := make(map[string]map[string]bool)
	scanner := newScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid manifest entry: %q", line)
		}

		source := normalizeName(parts[0])
		category := normalizeName(parts[1])
		if source == "" || category == "" {
			return nil, fmt.Errorf("invalid manifest entry: %q", line)
		}

		if result[source] == nil {
			result[source] = make(map[string]bool)
		}
		result[source][category] = true
	}
	return result, scanner.Err()
}

func loadOrderedCategories(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var categories []string
	seen := make(map[string]bool)
	scanner := newScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 || normalizeName(parts[0]) != "hydra" {
			return nil, fmt.Errorf("invalid Hydra append manifest entry: %q", line)
		}

		category := normalizeName(parts[1])
		if category == "" {
			return nil, fmt.Errorf("empty Hydra category in manifest: %q", line)
		}
		if seen[category] {
			return nil, fmt.Errorf("duplicate Hydra category in manifest: %q", category)
		}
		seen[category] = true
		categories = append(categories, category)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(categories) == 0 {
		return nil, fmt.Errorf("hydra append manifest is empty")
	}
	return categories, nil
}

type skipReason int

const (
	skipNone skipReason = iota
	skipBlank
	skipUnsupported
	skipInvalid
)

var unsupportedPrefixes = []string{
	"DOMAIN-KEYWORD,", "DOMAIN-REGEX,", "DOMAIN-WILDCARD,", "keyword:", "regexp:",
}

var typedPrefixes = []struct {
	prefix string
	typ    router.Domain_Type
	clash  bool
}{
	{"DOMAIN-SUFFIX,", router.Domain_RootDomain, true},
	{"DOMAIN-FULL,", router.Domain_Full, true},
	// Clash DOMAIN is an exact domain, so preserve Full semantics for BLOCK.
	{"DOMAIN,", router.Domain_Full, true},
	{"domain:", router.Domain_RootDomain, false},
	{"full:", router.Domain_Full, false},
}

func trimPrefixFold(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return s, false
}

func normalizeDomainValue(value string) string {
	value = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(value), "-"))
	for _, prefix := range []string{"+.", "*.", "."} {
		if strings.HasPrefix(value, prefix) {
			value = value[len(prefix):]
			break
		}
	}
	return strings.TrimSuffix(normalizeName(value), ".")
}

func parseRuleLine(raw string) (router.Domain_Type, string, skipReason) {
	line := strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
	if idx := strings.IndexByte(line, '#'); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	if line == "" {
		return 0, "", skipBlank
	}

	for _, prefix := range unsupportedPrefixes {
		if _, ok := trimPrefixFold(line, prefix); ok {
			return 0, "", skipUnsupported
		}
	}

	domainType := router.Domain_RootDomain
	for _, p := range typedPrefixes {
		if rest, ok := trimPrefixFold(line, p.prefix); ok {
			line, domainType = rest, p.typ
			if p.clash {
				if idx := strings.IndexByte(line, ','); idx >= 0 {
					line = line[:idx]
				}
			}
			break
		}
	}

	value := normalizeDomainValue(line)
	if !isValidDomain(value) {
		return 0, "", skipInvalid
	}
	return domainType, value, skipNone
}

type listStats struct {
	Rules       int
	Accepted    int
	Duplicates  int
	Unsupported int
	Invalid     int
	Samples     []string
}

func (s listStats) print(label string) {
	fmt.Printf("  %-32s rules=%-6d unique=%-6d dup=%-5d unsupported=%-4d invalid=%d\n",
		label, s.Rules, s.Accepted, s.Duplicates, s.Unsupported, s.Invalid)
	for _, sample := range s.Samples {
		fmt.Printf("    invalid sample: %q\n", sample)
	}
}

func scanRuleFile(path string, handle func(router.Domain_Type, string) bool) (listStats, error) {
	var stats listStats

	file, err := os.Open(path)
	if err != nil {
		return stats, err
	}
	defer file.Close()

	scanner := newScanner(file)
	for scanner.Scan() {
		domainType, value, reason := parseRuleLine(scanner.Text())
		if reason == skipBlank {
			continue
		}
		stats.Rules++

		switch reason {
		case skipUnsupported:
			stats.Unsupported++
		case skipInvalid:
			stats.Invalid++
			if len(stats.Samples) < 5 {
				stats.Samples = append(stats.Samples, strings.TrimSpace(scanner.Text()))
			}
		default:
			if handle(domainType, value) {
				stats.Accepted++
			} else {
				stats.Duplicates++
			}
		}
	}
	return stats, scanner.Err()
}

func loadDomainList(path string, requireNonEmpty bool, label string) ([]string, error) {
	var domains []string
	seen := make(map[string]bool)

	stats, err := scanRuleFile(path, func(_ router.Domain_Type, value string) bool {
		if seen[value] {
			return false
		}
		seen[value] = true
		domains = append(domains, value)
		return true
	})
	if err != nil {
		return nil, err
	}
	stats.print(label)

	if len(domains) == 0 && requireNonEmpty {
		return nil, fmt.Errorf("%s domain list is empty", label)
	}
	return domains, nil
}

func loadBlockDomainList(path, label string) ([]*router.Domain, error) {
	var domains []*router.Domain
	seen := make(map[string]bool)

	stats, err := scanRuleFile(path, func(domainType router.Domain_Type, value string) bool {
		key := domainValueKey(domainType, value)
		if seen[key] {
			return false
		}
		seen[key] = true
		domains = append(domains, &router.Domain{Type: domainType, Value: value})
		return true
	})
	if err != nil {
		return nil, err
	}
	stats.print(label)
	return domains, nil
}
