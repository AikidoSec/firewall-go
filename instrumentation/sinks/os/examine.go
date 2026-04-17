package os

import (
	"context"

	"github.com/AikidoSec/firewall-go/instrumentation/hooks"
	"github.com/AikidoSec/firewall-go/instrumentation/operation"
	"github.com/AikidoSec/firewall-go/vulnerabilities"
	"github.com/AikidoSec/firewall-go/vulnerabilities/pathtraversal"
	"github.com/AikidoSec/firewall-go/zen"
)

func ExamineOp(op, path string) error {
	if zen.IsDisabled() {
		return nil
	}

	hooks.OnOperationCall(op, operation.KindFileSystem)

	return vulnerabilities.ScanWithOptions(context.Background(), op, pathtraversal.PathTraversalVulnerability, &pathtraversal.ScanArgs{
		FilePath:       path,
		CheckPathStart: true,
	}, vulnerabilities.ScanOptions{
		DeferReporting: false,
		Module:         "os",
	})
}
