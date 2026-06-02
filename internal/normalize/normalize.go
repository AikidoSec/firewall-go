package normalize

import (
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"
)

// Hostname canonicalizes a hostname for comparison and storage: it strips a
// trailing dot, folds Unicode confusables (NFKC), and lowercases to Unicode.
// This makes "example.com."/"example.com", punycode/Unicode labels, and
// confusables like "ⓛocalhost"/"localhost" all compare equal.
func Hostname(hostname string) string {
	h := norm.NFKC.String(strings.TrimSuffix(hostname, "."))
	if unicode, err := idna.Lookup.ToUnicode(h); err == nil {
		return unicode
	}
	return strings.ToLower(h)
}
