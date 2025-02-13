package internal

import (
	"github.com/AikidoSec/firewall-go/internal/context"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/path_traversal"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/transits"
)

func DefineTransits() {
	if transits.PathTraversalFunction == nil {
		definePathTraversalFunction()
	}
}
func definePathTraversalFunction() {
	transits.PathTraversalFunction = func(file string) error {
		ctx := context.Get()
		if ctx == nil {
			return nil
		}

		return vulnerabilities.Scan(*ctx, path_traversal.PathTraversalVulnerability, []string{
			file /* checkPathStart */, "1",
		})
	}
}
