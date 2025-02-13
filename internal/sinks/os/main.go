package os

import (
	"github.com/AikidoSec/firewall-go/internal/context"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/path_traversal"
)

func Examine(path string) error {
	ctx := context.Get()
	if ctx == nil {
		return nil
	}
	return vulnerabilities.Scan(*ctx, path_traversal.PathTraversalVulnerability, []string{
		path /* checkPathStart */, "1",
	})
}
