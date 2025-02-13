package internal

import (
	"github.com/AikidoSec/firewall-go/internal/orchestrion/os"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/transits"
)

func DefineTransits() {
	if transits.PathTraversalFunction == nil {
		transits.PathTraversalFunction = os.Examine
	}
}
