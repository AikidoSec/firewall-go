package vulnerabilities

import (
	"errors"
	"github.com/AikidoSec/firewall-go/internal/context"
	"github.com/AikidoSec/firewall-go/internal/helpers"
	"github.com/AikidoSec/firewall-go/internal/types"
	"github.com/AikidoSec/zen-internals-agent/log"
)

type ScanResult struct {
	DetectedAttack bool
	Metadata       map[string]string
}
type Vulnerability struct {
	ScanFunction func(string, []string) *ScanResult
	Kind         types.Kind
	Error        string
}
type Attack struct {
	Kind string
}

func Scan(ctx context.Context, operation string, vulnerability Vulnerability, args []string) error {
	userInputMap := helpers.ExtractStringsFromUserInput(ctx.Query, []helpers.PathPart{})
	var attack *types.InterceptorResult = nil

	for userInput, path := range userInputMap {
		results := vulnerability.ScanFunction(userInput, args)
		if results != nil && results.DetectedAttack {
			// Attack detected :
			attack = &types.InterceptorResult{
				Operation:     operation,
				Kind:          vulnerability.Kind,
				Source:        "query",
				PathToPayload: path,
				Metadata:      results.Metadata,
				Payload:       userInput,
			}
			log.Debugf("Attack: %s", attack.ToString())

			break
		}
	}

	if attack != nil {
		return errors.New("Aikido: " + vulnerability.Error)
	}
	return nil
}
