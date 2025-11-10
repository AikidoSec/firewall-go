package os

import (
	"context"

	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/pathtraversal"
)

func Examine(path string) error {
	operation := "os.OpenFile"

	return vulnerabilities.Scan(context.Background(), operation, pathtraversal.PathTraversalVulnerability, &pathtraversal.ScanArgs{
		FilePath:       path,
		CheckPathStart: true,
	})
}
