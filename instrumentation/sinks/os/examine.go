package os

import (
	"context"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/state/stats"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/pathtraversal"
)

func Examine(path string) error {
	if config.IsZenDisabled() {
		return nil
	}

	agent.OnOperationCall("os.OpenFile", stats.OperationKindFileSystem)

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
