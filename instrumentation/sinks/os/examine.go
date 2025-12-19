package os

import (
	"context"

	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/pathtraversal"
	"github.com/AikidoSec/firewall-go/zen"
)

func Examine(path string) error {
	if zen.IsDisabled() {
		return nil
	}

	operation := "os.OpenFile"

	return vulnerabilities.Scan(context.Background(), operation, pathtraversal.PathTraversalVulnerability, &pathtraversal.ScanArgs{
		FilePath:       path,
		CheckPathStart: true,
	})
}
