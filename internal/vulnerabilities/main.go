package vulnerabilities

import (
	"errors"
	"github.com/AikidoSec/firewall-go/internal/context"
	"github.com/AikidoSec/firewall-go/internal/helpers"
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
	userInputMap := helpers.ExtractStringsFromUserInput(ctx.Query, []helpers.PathPart{})
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
