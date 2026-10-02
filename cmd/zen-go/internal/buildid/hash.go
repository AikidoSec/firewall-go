package buildid

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/AikidoSec/firewall-go/cmd/zen-go/internal/instrumentor"
)

// ComputeInstrumentationHash hashes the zen-go version, raw rule files, and added
// source files. Go uses this hash in its tool ID before deciding whether to compile.
func ComputeInstrumentationHash(inst *instrumentor.Instrumentor, version string) string {
	h := sha256.New()
	fmt.Fprintf(h, "version:%q\n", version)

	// Hash raw bytes so new rule types and fields are covered automatically.
	// Changing rule order can change the transformations applied.
	for _, content := range inst.SourceFiles {
		fmt.Fprintf(h, "rules:%x\n", sha256.Sum256(content))
	}

	for _, rule := range inst.AddFileRules {
		// #nosec G304 -- FilePath is resolved from the trusted instrumentation directory
		content, err := os.ReadFile(rule.FilePath)
		if err != nil {
			// Compilation warns and skips unreadable files. Record that state without
			// hashing machine-dependent paths or error strings, or failing the build.
			fmt.Fprintln(h, "add-file:unreadable")
			continue
		}
		fmt.Fprintf(h, "add-file:%x\n", sha256.Sum256(content))
	}

	return base64.URLEncoding.EncodeToString(h.Sum(nil))[:16]
}
