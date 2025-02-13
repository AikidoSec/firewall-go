package os

import (
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/transits"
)

func Examine(path string) error {
	if transits.PathTraversalFunction != nil {
		return transits.PathTraversalFunction(path)
	}
	return nil
}
