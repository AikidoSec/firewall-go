package vulnerabilities

import (
	"errors"

	"github.com/AikidoSec/firewall-go/internal/context"
	"github.com/AikidoSec/firewall-go/internal/helpers"
	"github.com/AikidoSec/zen-internals-agent/log"
)

type ScanResult struct {
	DetectedAttack bool
	Metadata       map[string]string
}
type Vulnerability struct {
	ScanFunction func(string, []string) *ScanResult
	Kind         AttackKind
	Error        string
}
type Attack struct {
	Kind string
}

func Scan(ctx context.Context, operation string, vulnerability Vulnerability, args []string) error {
	err := ScanSource("query", ctx.Query, operation, vulnerability, args)
	if err != nil {
		return err
	}
	err = ScanSource("headers", ctx.Headers, operation, vulnerability, args)
	if err != nil {
		return err
	}
	err = ScanSource("cookies", ctx.Cookies, operation, vulnerability, args)
	if err != nil {
		return err
	}
	err = ScanSource("body", ctx.Body, operation, vulnerability, args)
	if err != nil {
		return err
	}
	return nil
}

func ScanSource(source string, sourceData any, operation string, vulnerability Vulnerability, args []string) error {
	userInputMap := helpers.ExtractStringsFromUserInput(sourceData, []helpers.PathPart{})

	for userInput, path := range userInputMap {
		results := vulnerability.ScanFunction(userInput, args)
		if results != nil && results.DetectedAttack {
			// Attack detected :
			attack := &InterceptorResult{
				Operation:     operation,
				Kind:          vulnerability.Kind,
				Source:        source,
				PathToPayload: path,
				Metadata:      results.Metadata,
				Payload:       userInput,
			}
			log.Debugf("Attack: %s", attack.ToString())
			ReportAttackDetected(attack)

			return errors.New("Aikido: " + vulnerability.Error)
		}
	}

	return nil
}
