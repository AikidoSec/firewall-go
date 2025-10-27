package vulnerabilities

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"maps"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
	"github.com/AikidoSec/firewall-go/internal/request"
)

type AttackKind string

const (
	KindSQLInjection   AttackKind = "sql_injection"
	KindPathTraversal  AttackKind = "path_traversal"
	KindShellInjection AttackKind = "shell_injection"
	KindSSRF           AttackKind = "ssrf"
)

func getDisplayNameForAttackKind(kind AttackKind) string {
	switch kind {
	case KindSQLInjection:
		return "an SQL injection"
	case KindPathTraversal:
		return "a path traversal attack"
	case KindShellInjection:
		return "a shell injection"
	case KindSSRF:
		return "a server-side request forgery"
	default:
		return "unknown attack type"
	}
}

type InterceptorResult struct {
	Kind          AttackKind
	Operation     string
	Source        string
	PathToPayload string
	Metadata      map[string]string
	Payload       string
}

func (i InterceptorResult) ToString() string {
	json, _ := json.Marshal(i)
	return string(json)
}

// getHeaders clones headers map to be sent to the Agent
func getHeaders(context *request.Context) map[string][]string {
	headers := make(map[string][]string)
	for key, value := range context.Headers {
		headers[key] = append([]string{}, value...)
	}
	return headers
}

func getAttackDetected(ctx context.Context, res InterceptorResult) *aikido_types.DetectedAttack {
	reqCtx := request.GetContext(ctx)
	if reqCtx == nil {
		return nil
	}

	return &aikido_types.DetectedAttack{
		Request: aikido_types.RequestInfo{
			Method:    reqCtx.Method,
			IPAddress: *reqCtx.RemoteAddress,
			UserAgent: reqCtx.GetUserAgent(),
			URL:       reqCtx.URL,
			Headers:   getHeaders(reqCtx),
			Body:      reqCtx.GetBodyRaw(),
			Source:    reqCtx.Source,
			Route:     reqCtx.Route,
		},
		Attack: aikido_types.AttackDetails{
			Kind:      string(res.Kind),
			Operation: res.Operation,
			Module:    "Module",
			Blocked:   config.IsBlockingEnabled(),
			Source:    res.Source,
			Path:      res.PathToPayload,
			Payload:   res.Payload,
			Metadata:  maps.Clone(res.Metadata),
			User:      utils.GetUserByID(reqCtx.GetUserID()),
		},
	}
}

func buildAttackDetectedError(result InterceptorResult) error {
	return fmt.Errorf("aikido firewall has blocked %s: %s(...) originating from %s%s",
		getDisplayNameForAttackKind(result.Kind),
		result.Operation,
		result.Source,
		html.EscapeString(result.PathToPayload))
}

// onInterceptorResult sends the detected attack to the cloud
// Returns an error indicating the request should be blocked if blocking is enabled.
func onInterceptorResult(ctx context.Context, res *InterceptorResult) error {
	if res == nil {
		return nil
	}

	atk := getAttackDetected(ctx, *res)
	go agent.OnAttackDetected(atk)

	// If blocking is enabled, continue as normal after reporting the attack.
	if atk == nil || !atk.Attack.Blocked {
		return nil
	}

	return buildAttackDetectedError(*res)
}
