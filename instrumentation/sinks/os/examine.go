package os

import (
	"context"

	"github.com/AikidoSec/firewall-go/instrumentation/hooks"
	"github.com/AikidoSec/firewall-go/vulnerabilities"
	"github.com/AikidoSec/firewall-go/vulnerabilities/pathtraversal"
	"github.com/AikidoSec/firewall-go/zen"
)

func Examine(path string) error {
	if zen.IsDisabled() {
		return nil
	}

	hooks.OnOperationCall("os.OpenFile", hooks.OperationKindFileSystem)

	// The error that the vulnerability scan returns is NOT deferred with os.OpenFile
	// We block and report immediately
	err := vulnerabilities.ScanWithOptions(context.Background(), "os.OpenFile", pathtraversal.PathTraversalVulnerability, &pathtraversal.ScanArgs{
		FilePath:       path,
		CheckPathStart: true,
	}, vulnerabilities.ScanOptions{
		DeferReporting: false,
	})

	return err
}
