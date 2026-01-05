package vulnerabilities

import (
	"context"
	"log/slog"

	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/endpoints"
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

type ScanOptions struct {
	DeferReporting bool
}

func Scan[T any](ctx context.Context, operation string, vulnerability Vulnerability[T], args T) error {
	return ScanWithOptions(ctx, operation, vulnerability, args, ScanOptions{})
}

func ScanWithOptions[T any](ctx context.Context, operation string, vulnerability Vulnerability[T], args T, opts ScanOptions) error {
	if config.IsZenDisabled() {
		return nil
	}

	reqCtx := request.GetContext(ctx)
	if reqCtx == nil {
		return nil
	}

	// Check if route has force protection off, if so, we don't run any scans
	matches := endpoints.FindMatches(
		config.GetEndpoints(),
		endpoints.RouteMetadata{
			Method: reqCtx.Method,
			Route:  reqCtx.Route,
		},
	)
	for _, match := range matches {
		if match.ForceProtectionOff {
			return nil
		}
	}

	deferredAttack := reqCtx.GetDeferredAttack()
	if deferredAttack != nil && deferredAttack.Kind == string(vulnerability.Kind) {
		reportDeferredAttack(ctx)

		// If blocking is enabled, there will be an error to return to block the request
		if deferredAttack.Error != nil {
			return deferredAttack.Error
		}
	}

	err := scanSource(ctx, "query", reqCtx.Query, operation, vulnerability, args, opts)
	if err != nil {
		return err
	}

	err = scanSource(ctx, "headers", reqCtx.Headers, operation, vulnerability, args, opts)
	if err != nil {
		return err
	}

	err = scanSource(ctx, "cookies", reqCtx.Cookies, operation, vulnerability, args, opts)
	if err != nil {
		return err
	}

	err = scanSource(ctx, "routeParams", reqCtx.RouteParams, operation, vulnerability, args, opts)
	if err != nil {
		return err
	}

	err = scanSource(ctx, "body", reqCtx.Body, operation, vulnerability, args, opts)
	if err != nil {
		return err
	}
	return nil
}

func scanSource[T any](ctx context.Context, source string, sourceData any, operation string, vulnerability Vulnerability[T], args T, opts ScanOptions) error {
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

			if opts.DeferReporting {
				return storeDeferredAttack(ctx, attack)
			}
			return onInterceptorResult(ctx, attack)
		}
	}

	return nil
}
