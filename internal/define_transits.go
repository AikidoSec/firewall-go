package internal

import (
	"context"

	"github.com/AikidoSec/firewall-go/internal/transits"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/pathtraversal"
)

// DefineTransits helps define transit functions. These are functions we cannot directly call
// because then the compiler crashes. This is due to the fact that our code gets inserted on compile of e.g. `os`.
// Our code then uses the `os` module resulting in a stuck compile loop.
func DefineTransits() {
	if transits.GetOSSinkFunction() == nil {
		transits.SetOSSinkFunction(OSExamine)
	}
}

func OSExamine(path string) error {
	operation := "os.OpenFile"

	return vulnerabilities.Scan(context.Background(), operation, pathtraversal.PathTraversalVulnerability, []string{
		path /* checkPathStart */, "1",
	})
}
