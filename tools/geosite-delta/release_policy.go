package main

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"sort"
	"strconv"
	"strings"
)

func verifyRoutingDecisions(ru rules, reviews map[string]reviewDecision) error {
	// User-selected no-DIRECT subtree. Independent of external inventory and
	// review file: removing a TSV line cannot weaken this routing policy.
	for _, domain := range []string{"4pda.to", "www.4pda.to"} {
		if reviews[domain].status != "reject" {
			return fmt.Errorf("mandatory no-DIRECT policy missing reject decision for %s", domain)
		}
	}
	if conflict := rejectedSubtreeConflict(ru, "4pda.to"); conflict != "" {
		return fmt.Errorf("4pda.to no-DIRECT subtree policy violated: %s", conflict)
	}
	for domain, review := range reviews {
		isRU := covered(ru, domain, false)
		// A generic reject is exact to this domain, NOT a blanket ban for all
		// descendants: shared Akamai/Cloudflare CDNs can host RU-specific services.
		if review.status == "reject" && isRU {
			return fmt.Errorf("rejected external domain %s is unexpectedly covered by RU", domain)
		}
		if review.status == "hold" && isRU {
			return fmt.Errorf("external domain %s is on HOLD pending routing approval but has RU coverage", domain)
		}
		if review.status == "confirmed" && !isRU {
			return fmt.Errorf("confirmed candidate %s is missing from RU", domain)
		}
	}
	if covered(ru, "stream.kick.com", false) {
		return fmt.Errorf("stream.kick.com is excluded from RU, including coverage by any parent rule")
	}
	return nil
}

// Compare the exact typed rule sets outside RU. This catches missing/added
// categories and type changes even when a suffix masks an exact rule.
func changedProtectedCategories(old, now map[string]rules) []string {
	changed := map[string]bool{}
	for c, a := range old {
		if c == "RU" {
			continue
		}
		b, present := now[c]
		if !present || !maps.Equal(a.roots, b.roots) || !maps.Equal(a.full, b.full) || !maps.Equal(a.opaque, b.opaque) {
			changed[c] = true
		}
	}
	for c := range now {
		if _, present := old[c]; c != "RU" && !present {
			changed[c] = true
		}
	}
	out := make([]string, 0, len(changed))
	for c := range changed {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func writeSemanticDelta(path string, old, now map[string]rules) (addedRU, lostRU, changed []string, err error) {
	var b, details strings.Builder
	fmt.Fprint(&b, "# Semantic comparison: release DAT vs candidate\n\n")
	fmt.Fprint(&b, "Rules are compared by effective suffix/full-domain coverage. The gate also protects exact typed rule sets outside RU.\n\n")
	fmt.Fprint(&b, "| Category | Release rules | Candidate rules | Newly covered rules | No longer covered rules |\n|---|---:|---:|---:|---:|\n")
	cats := map[string]bool{}
	for c := range old {
		cats[c] = true
	}
	for c := range now {
		cats[c] = true
	}
	keys := make([]string, 0, len(cats))
	for c := range cats {
		keys = append(keys, c)
	}
	sort.Strings(keys)
	for _, c := range keys {
		a, z := old[c], now[c]
		add, lost := differences(z, a), differences(a, z)
		before, after := len(a.roots)+len(a.full)+len(a.opaque), len(z.roots)+len(z.full)+len(z.opaque)
		fmt.Printf("DELTA %s: release=%d candidate=%d newly_covered=%d lost=%d\n", c, before, after, len(add), len(lost))
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d |\n", c, before, after, len(add), len(lost))
		if c == "RU" {
			addedRU, lostRU = add, lost
		}
		fmt.Fprintf(&details, "\n## %s — added effective rules (%d)\n\n", c, len(add))
		for _, v := range add {
			fmt.Fprintf(&details, "- `%s`\n", v)
		}
		fmt.Fprintf(&details, "\n## %s — no longer covered (%d)\n\n", c, len(lost))
		for _, v := range lost {
			fmt.Fprintf(&details, "- `%s`\n", v)
		}
	}
	changed = changedProtectedCategories(old, now)
	if len(changed) > 0 {
		fmt.Fprintf(&b, "\nProtected category changes (including rule type and presence): **%s**.\n", strings.Join(changed, ", "))
	}
	err = os.WriteFile(path, []byte(b.String()+details.String()), 0644)
	return
}

func verifyCategoryTransition(old, now map[string]rules, addedRU, lostRU, changed []string) error {
	if _, ok := old["RU"]; !ok {
		return fmt.Errorf("comparison base is missing RU")
	}
	if _, ok := now["RU"]; !ok {
		return fmt.Errorf("candidate is missing RU")
	}
	if _, ok := old["BLOCK"]; !ok {
		return fmt.Errorf("comparison base is missing BLOCK")
	}
	if _, ok := now["BLOCK"]; !ok {
		return fmt.Errorf("candidate is missing BLOCK")
	}
	if len(changed) > 0 {
		return fmt.Errorf("unreviewed protected category changes: %s", strings.Join(changed, ", "))
	}
	if len(lostRU) > 0 {
		return fmt.Errorf("%d release RU rules no longer covered; review before merge", len(lostRU))
	}
	if raw := os.Getenv("GEOSITE_EXPECTED_RU_ADDITIONS"); raw != "" {
		expected, err := strconv.Atoi(raw)
		if err != nil || expected < 0 || expected != len(addedRU) {
			return fmt.Errorf("release promotion expected %q RU additions; got %d", raw, len(addedRU))
		}
	}
	return nil
}

func checkRelease(paths []string) error {
	rolling, err := decode(paths[0])
	if err != nil {
		return fmt.Errorf("rolling DAT: %w", err)
	}
	locked, err := decode(paths[1])
	if err != nil {
		return fmt.Errorf("locked DAT: %w", err)
	}
	now, err := decode(paths[2])
	if err != nil {
		return fmt.Errorf("candidate DAT: %w", err)
	}
	added, lost, changed, err := writeSemanticDelta(paths[3], rolling, now)
	if err != nil {
		return err
	}
	if err = verifyCategoryTransition(rolling, now, added, lost, changed); err != nil {
		return err
	}
	if err = verifyCategoryTransition(locked, now, added, differences(locked["RU"], now["RU"]),
		changedProtectedCategories(locked, now)); err != nil {
		return fmt.Errorf("locked release floor: %w", err)
	}
	reviews, err := loadReviewDecisions(paths[5])
	if err != nil {
		return err
	}
	if err = verifyRoutingDecisions(now["RU"], reviews); err != nil {
		return err
	}
	// A self-consistent rolling DAT and checksum are not a trust anchor.
	// A rolling-only rule must also be approved against the locked floor.
	if err = verifyReviewedAdditions(paths[4], differences(now["RU"], locked["RU"]), now["RU"]); err != nil {
		if len(added) == 0 {
			return fmt.Errorf("candidate matches rolling coverage but is inconsistent with locked release policy: %v", err)
		}
		// Only a delta absent from rolling may become the weekly review queue.
		var pending *pendingRUReview
		if errors.As(err, &pending) {
			rollingAdds := make(map[string]bool, len(added))
			for _, rule := range added {
				rollingAdds[rule] = true
			}
			for _, rule := range pending.rules {
				if !rollingAdds[rule] {
					return fmt.Errorf("rolling baseline contains unapproved RU rule %s", rule)
				}
			}
		}
		return err
	}
	fmt.Printf("PRODUCTION_RU_APPROVAL count=%d exact_match=true\n", len(added))
	return nil
}
