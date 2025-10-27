package vulnerabilities

import (
	"context"
	"log/slog"

	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/request"
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
	reqCtx := request.GetContext(ctx)
	if reqCtx == nil {
		return nil
	}

	detectedAttack, err := scanSource(ctx, "query", reqCtx.Query, operation, vulnerability, args)
	if detectedAttack || err != nil {
		return err
	}

	detectedAttack, err = scanSource(ctx, "headers", reqCtx.Headers, operation, vulnerability, args)
	if detectedAttack || err != nil {
		return err
	}

	detectedAttack, err = scanSource(ctx, "cookies", reqCtx.Cookies, operation, vulnerability, args)
	if detectedAttack || err != nil {
		return err
	}

	detectedAttack, err = scanSource(ctx, "body", reqCtx.Body, operation, vulnerability, args)
	if detectedAttack || err != nil {
		return err
	}
	return nil
}

// scanSource returns a boolean if an attack was detected and an error to be returned to the sink if the attack should be blocked
func scanSource(ctx context.Context, source string, sourceData any, operation string, vulnerability Vulnerability, args []string) (bool, error) {
	userInputMap := extractStringsFromUserInput(sourceData, []pathPart{})

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
			log.Debug("Attack", slog.String("attack", attack.ToString()))

			return true, onInterceptorResult(ctx, attack)
		}
	}

	return false, nil
}
