package internal

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sort"

	"github.com/AikidoSec/firewall-go/cmd/zen-go/internal/instrumentor"
)

// ComputeInstrumentationHash computes a hash of all instrumentation rules and the zen-go version.
// This hash is used to modify the build ID so that when rules or the version change, Go will rebuild packages.
func ComputeInstrumentationHash(inst *instrumentor.Instrumentor, version string) string {
	h := sha256.New()

	// Hash the zen-go version
	fmt.Fprintf(h, "version:%s\n", version)

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

	// Hash prepend rules
	for _, rule := range inst.PrependRules {
		fmt.Fprintf(h, "prepend:%s:%s:%s:", rule.ID, rule.ReceiverType, rule.Package)
		// Sort function names for consistent hashing
		funcNames := make([]string, len(rule.FuncNames))
		copy(funcNames, rule.FuncNames)
		sort.Strings(funcNames)
		for _, fn := range funcNames {
			fmt.Fprintf(h, "%s:", fn)
		}
		// Sort imports for consistent hashing
		importKeys := make([]string, 0, len(rule.Imports))
		for k := range rule.Imports {
			importKeys = append(importKeys, k)
		}
		sort.Strings(importKeys)
		for _, k := range importKeys {
			fmt.Fprintf(h, "%s=%s:", k, rule.Imports[k])
		}
		fmt.Fprintf(h, "%s\n", rule.PrependTmpl)
	}

	// Hash inject decl rules
	for _, rule := range inst.InjectDeclRules {
		fmt.Fprintf(h, "inject-decl:%s:%s:%s:", rule.ID, rule.Package, rule.AnchorFunc)
		// Sort links for consistent hashing
		links := make([]string, len(rule.Links))
		copy(links, rule.Links)
		sort.Strings(links)
		for _, link := range links {
			fmt.Fprintf(h, "%s:", link)
		}
		fmt.Fprintf(h, "%s\n", rule.DeclTemplate)
	}

	// Return base64-encoded hash (first 16 chars for brevity)
	hash := h.Sum(nil)
	return base64.URLEncoding.EncodeToString(hash)[:16]
}
