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

func ExamineDeferred(operationName string, args []string) error {
	if zen.IsDisabled() {
		return nil
	}

	hooks.OnOperationCall(operationName, operation.KindFileSystem)

	path := strings.Join(args, "")

	// The error that the vulnerability scan returns is deferred
	// We delay blocking and reporting until the result is used in os.OpenFile
	return vulnerabilities.ScanWithOptions(context.Background(), operationName, pathtraversal.PathTraversalVulnerability, &pathtraversal.ScanArgs{
		FilePath:       path,
		CheckPathStart: true,
	}, vulnerabilities.ScanOptions{
		DeferReporting: true,
		Module:         "path",
	})
}
