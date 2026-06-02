package filepath

import (
	"context"
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

// ExamineDeferredArg is the hook entry point for deferred path-building functions that take a single string path (e.g. Clean).
func ExamineDeferredArg(operationName, arg string) error {
	return ExamineDeferred(operationName, []string{arg})
}

// ExamineDeferred is the hook entry point for path-building functions that cannot return an error (e.g. Join).
// Blocking is deferred until the result is used in a filesystem operation.
func ExamineDeferred(operationName string, elems []string) error {
	if zen.IsDisabled() {
		return nil
	}

	hooks.OnOperationCall(operationName, operation.KindFileSystem)

	path := strings.Join(elems, "")

	return vulnerabilities.ScanWithOptions(context.Background(), operationName, pathtraversal.PathTraversalVulnerability, &pathtraversal.ScanArgs{
		FilePath:       path,
		CheckPathStart: true,
	}, vulnerabilities.ScanOptions{
		DeferReporting: true,
		Module:         "path/filepath",
	})
}
