package internal

import (
	"github.com/AikidoSec/firewall-go/internal/context"
	"github.com/AikidoSec/firewall-go/internal/transits"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/path_traversal"
)

// DefineTransits helps define transit functions. These are functions we cannot directly call
// because then the compiler crashes. This is due to the fact that our code gets inserted on compile of e.g. `os`.
// Our code then uses the `os` module resulting in a stuck compile loop.
func DefineTransits() {
	if transits.OSSinkFunction == nil {
		transits.OSSinkFunction = OSExamine
	}
}

func OSExamine(path string) error {
	ctx := context.Get()
	if ctx == nil {
		return nil
	}
	return vulnerabilities.Scan(*ctx, path_traversal.PathTraversalVulnerability, []string{
		path /* checkPathStart */, "1",
	})
}
