package filepath

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/AikidoSec/firewall-go/instrumentation/hooks"
	"github.com/AikidoSec/firewall-go/instrumentation/operation"
	"github.com/AikidoSec/firewall-go/vulnerabilities"
	"github.com/AikidoSec/firewall-go/vulnerabilities/pathtraversal"
	"github.com/AikidoSec/firewall-go/zen"
)

// Examine is the hook entry point for functions that directly open the filesystem (e.g. Walk, WalkDir, Glob).
func Examine(operationName, path string) error {
	if zen.IsDisabled() {
		return nil
	}

	hooks.OnOperationCall(operationName, operation.KindFileSystem)

	return vulnerabilities.ScanWithOptions(context.Background(), operationName, pathtraversal.PathTraversalVulnerability, &pathtraversal.ScanArgs{
		FilePath:       path,
		CheckPathStart: true,
	}, vulnerabilities.ScanOptions{
		DeferReporting: false,
		Module:         "path/filepath",
	})
}

// ExamineDeferred is the hook entry point for path-building functions that cannot return an error (e.g. Join).
// Blocking is deferred until the result is used in a filesystem operation.
func ExamineDeferred(operationName string, elems []string) error {
	if zen.IsDisabled() {
		return nil
	}

	hooks.OnOperationCall(operationName, operation.KindFileSystem)

	// Join with the OS-specific separator to preserve path segment boundaries for traversal detection.
	// This ensures split-segment traversal (e.g., filepath.Join(base, "..", file))
	// is properly detected by matching the normalized form that filepath.Join produces.
	path := strings.Join(elems, string(filepath.Separator))

	return vulnerabilities.ScanWithOptions(context.Background(), operationName, pathtraversal.PathTraversalVulnerability, &pathtraversal.ScanArgs{
		FilePath:       path,
		CheckPathStart: true,
	}, vulnerabilities.ScanOptions{
		DeferReporting: true,
		Module:         "path/filepath",
	})
}
