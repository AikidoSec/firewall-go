package path

import (
	"context"
	"strings"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/state/stats"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/pathtraversal"
)

func Examine(args []string) error {
	if config.IsZenDisabled() {
		return nil
	}

	agent.OnOperationCall("path.Join", stats.OperationKindFileSystem)

	path := strings.Join(args, "")

	// The error that the vulnerability scan returns is deferred with path.Join
	// We delay blocking and reporting until the result is used in os.OpenFile
	err := vulnerabilities.ScanWithOptions(context.Background(), "path.Join", pathtraversal.PathTraversalVulnerability, &pathtraversal.ScanArgs{
		FilePath:       path,
		CheckPathStart: true,
	}, vulnerabilities.ScanOptions{
		DeferReporting: true,
	})

	return err
}
