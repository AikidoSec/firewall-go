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

func Examine(args []string) error {
	if zen.IsDisabled() {
		return nil
	}

	hooks.OnOperationCall("path.Join", operation.KindFileSystem)

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
