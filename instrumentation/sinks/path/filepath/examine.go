package filepath
<<<<<<< HEAD
=======

import (
	"context"
	"strings"

	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/pathtraversal"
	"github.com/AikidoSec/firewall-go/zen"
)

func Examine(args []string) {
	if zen.IsDisabled() {
		return
	}

	path := strings.Join(args, "")

	// The error that the vulnerability scan returns is deferred with filepath.Join
	// We delay blocking and reporting until the result is used in os.OpenFile
	_ = vulnerabilities.ScanWithOptions(context.Background(), "filepath.Join", pathtraversal.PathTraversalVulnerability, &pathtraversal.ScanArgs{
		FilePath:       path,
		CheckPathStart: true,
	}, vulnerabilities.ScanOptions{
		DeferReporting: true,
	})
}
>>>>>>> 32c672b (Add support for AIKIDO_DISABLE)
