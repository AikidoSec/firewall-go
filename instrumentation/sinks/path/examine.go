package path

import (
	"context"
	"strings"

	"github.com/AikidoSec/firewall-go/instrumentation/hooks"
	"github.com/AikidoSec/firewall-go/instrumentation/operation"
	"github.com/AikidoSec/firewall-go/vulnerabilities"
	"github.com/AikidoSec/firewall-go/vulnerabilities/pathtraversal"
	"github.com/AikidoSec/firewall-go/zen"
)

// ExamineArg is the hook entry point for functions that take a single string path (e.g. Clean).
func ExamineArg(op, arg string) error {
	return Examine(op, []string{arg})
}

func Examine(op string, args []string) error {
	if zen.IsDisabled() {
		return nil
	}

	hooks.OnOperationCall(op, operation.KindFileSystem)

	path := strings.Join(args, "")

	// The error that the vulnerability scan returns is deferred
	// We delay blocking and reporting until the result is used in os.OpenFile
	return vulnerabilities.ScanWithOptions(context.Background(), op, pathtraversal.PathTraversalVulnerability, &pathtraversal.ScanArgs{
		FilePath:       path,
		CheckPathStart: true,
	}, vulnerabilities.ScanOptions{
		DeferReporting: true,
		Module:         "path",
	})
}
