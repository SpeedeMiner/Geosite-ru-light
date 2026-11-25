// Package ruunregistered records the time-sensitive, reviewed RU exclusions.
// Original registration review: 2026-11-24; two additions reviewed 2026-11-25.
// Revisit these exclusions when a legitimate
// service is restored. These names are not added to the BLOCK category.
package ruunregistered

var domains = [...]string{
	"aksyuterian.com",
	"aodahl.com",
	"avito-services.com",
	"bluestacksads.com",
	"bluestacksapi.com",
	"bluestackscdn.com",
	"bluestackscloud.com",
	"bluestacksdata.com",
	"bluestacksengine.com",
	"bonus-card.ml",
	"cdn-tinkoff.com",
	"honestmark.org",
	"investalfabank.com",
	"lead-pro2023.online",
	"rosbank-credit.com",
	"russieactuelle.fr",
	"sberfinance.net",
	"sbruss.store",
	"smsemailstats.com",
	"tbankjob.site",
	"tinkoff-anketa.site",
	"tinkoff-digital.com",
	"tinkoffdigital.com",
	"tinkoffip.site",
	"tinkoffreg.site",
	"tynkoff.cc",
	"vk.cloud",
	"vkcache.com",
	"vkusvill.net",
	"vtbkep.site",
	"xn--90aifd0aza.site",
}

// Names returns a copy so callers cannot mutate the routing policy.
func Names() []string {
	return append([]string(nil), domains[:]...)
}

// Contains reports exact membership; subtree matching is implemented by callers.
func Contains(name string) bool {
	for _, domain := range domains {
		if name == domain {
			return true
		}
	}
	return false
}
