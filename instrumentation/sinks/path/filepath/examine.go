package filepath

import (
	"context"
	pathfilepath "path/filepath"
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

	// Reconstruct the path by joining elements with the OS path separator.
	// We cannot use strings.Join(elems, "") because that would concatenate without separators,
	// causing bare ".." elements to not be detected (e.g., []string{"/tmp/", "..", "etc"} 
	// would become "/tmp/..etc" instead of "/tmp/../etc").
	// We also cannot use filepath.Join(elems...) because it normalizes the path, removing
	// the traversal markers we need to detect (e.g., "/tmp/../etc" becomes "/etc").
	path := strings.Join(elems, string(pathfilepath.Separator))

	return vulnerabilities.ScanWithOptions(context.Background(), operationName, pathtraversal.PathTraversalVulnerability, &pathtraversal.ScanArgs{
		FilePath:       path,
		CheckPathStart: true,
	}, vulnerabilities.ScanOptions{
		DeferReporting: true,
		Module:         "path/filepath",
	})
}
