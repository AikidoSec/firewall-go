package internal

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sort"
)

// ComputeInstrumentationHash computes a hash of all instrumentation rules.
// This hash is used to modify the build ID so that when rules change, Go will rebuild packages.
func ComputeInstrumentationHash(inst *Instrumentor) string {
	h := sha256.New()

	// Hash wrap rules
	for _, rule := range inst.WrapRules {
		fmt.Fprintf(h, "wrap:%s:%s:", rule.ID, rule.MatchCall)
		// Sort imports for consistent hashing
		importKeys := make([]string, 0, len(rule.Imports))
		for k := range rule.Imports {
			importKeys = append(importKeys, k)
		}
		sort.Strings(importKeys)
		for _, k := range importKeys {
			fmt.Fprintf(h, "%s=%s:", k, rule.Imports[k])
		}
		fmt.Fprintf(h, "%s\n", rule.WrapTmpl)
	}

	// Return base64-encoded hash (first 16 chars for brevity)
	hash := h.Sum(nil)
	return base64.URLEncoding.EncodeToString(hash[:])[:16]
}

