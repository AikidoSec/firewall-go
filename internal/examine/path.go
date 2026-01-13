package examine

import (
	"context"
	"strings"

	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/pathtraversal"
)

func examinePath(operation string, args []string, deferReporting bool) error {
	if config.IsZenDisabled() {
		return nil
	}

	path := strings.Join(args, "")

	// The error that the vulnerability scan returns is deferred with path.Join
	// We delay blocking and reporting until the result is used in os.OpenFile
	err := vulnerabilities.ScanWithOptions(context.Background(), operation, pathtraversal.PathTraversalVulnerability, &pathtraversal.ScanArgs{
		FilePath:       path,
		CheckPathStart: true,
	}, vulnerabilities.ScanOptions{
		DeferReporting: deferReporting,
	})

	return err
}
