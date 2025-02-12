package vulnerabilities

import (
	"errors"
	"github.com/AikidoSec/firewall-go/internal/context"
)

type Vulnerability struct {
	ScanFunction func(string, []string) bool
	Name         string
	Error        string
}
type Attack struct {
	Kind string
}

func Scan(ctx context.Context, vulnerability Vulnerability, args []string) error {
	userInputMap := context.ExtractStrings(ctx.Query)
	var attack *Attack = nil

	for userInput, _ := range userInputMap {
		if vulnerability.ScanFunction(userInput, args) {
			// Attack detected :

			attack = &Attack{
				Kind: vulnerability.Name,
			}

			break
		}
	}

	if attack != nil {
		return errors.New("Aikido: " + vulnerability.Error)
	}
	return nil
}
