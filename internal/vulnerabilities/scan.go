package vulnerabilities

import (
	"context"
	"errors"
	"log/slog"

	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/request"
)

type ScanResult struct {
	DetectedAttack bool
	Metadata       map[string]string
}

type Vulnerability[T any] struct {
	ScanFunction func(string, T) (*ScanResult, error)
	Kind         AttackKind
	Error        string
}

type Attack struct {
	Kind string
}

func Scan[T any](ctx context.Context, operation string, vulnerability Vulnerability[T], args T) error {
	reqCtx := request.GetContext(ctx)
	if reqCtx == nil {
		return nil
	}

	if deferred := reqCtx.GetDeferredBlock(); deferred != nil {
		// Check if the deferred block is for the same type of vulnerability
		var detectedErr *AttackDetectedError
		if errors.As(deferred, &detectedErr) {
			if detectedErr.Kind == vulnerability.Kind {
				return reqCtx.GetDeferredBlock()
			}
		}
	}

	err := scanSource(ctx, "query", reqCtx.Query, operation, vulnerability, args)
	if err != nil {
		return err
	}

	err = scanSource(ctx, "headers", reqCtx.Headers, operation, vulnerability, args)
	if err != nil {
		return err
	}

	err = scanSource(ctx, "cookies", reqCtx.Cookies, operation, vulnerability, args)
	if err != nil {
		return err
	}

	err = scanSource(ctx, "body", reqCtx.Body, operation, vulnerability, args)
	if err != nil {
		return err
	}
	return nil
}

func scanSource[T any](ctx context.Context, source string, sourceData any, operation string, vulnerability Vulnerability[T], args T) error {
	userInputMap := extractStringsFromUserInput(sourceData, []pathPart{})

	for userInput, path := range userInputMap {
		results, err := vulnerability.ScanFunction(userInput, args)
		if err != nil {
			log.Error("Scan error",
				slog.String("kind", string(vulnerability.Kind)),
				slog.String("operation", operation),
				slog.Any("error", err))
			continue
		}

		if results != nil && results.DetectedAttack {
			attack := &InterceptorResult{
				Operation:     operation,
				Kind:          vulnerability.Kind,
				Source:        source,
				PathToPayload: path,
				Metadata:      results.Metadata,
				Payload:       userInput,
			}
			log.Debug("Attack", slog.String("attack", attack.ToString()))

			return onInterceptorResult(ctx, attack)
		}
	}

	return nil
}
