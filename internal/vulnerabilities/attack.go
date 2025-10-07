package vulnerabilities

import (
	"encoding/json"
	"fmt"
	"html"
	"maps"

	"github.com/AikidoSec/firewall-go/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/agent/utils"
	"github.com/AikidoSec/firewall-go/internal/context"
	"github.com/AikidoSec/firewall-go/internal/grpc"
)

type AttackKind string

const (
	KindSQLInjection  AttackKind = "sql_injection"
	KindPathTraversal AttackKind = "path_traversal"
	KindSSRF          AttackKind = "ssrf"
)

func GetDisplayNameForAttackKind(kind AttackKind) string {
	switch kind {
	case KindSQLInjection:
		return "an SQL injection"
	case KindPathTraversal:
		return "a path traversal attack"
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
func getHeaders(context *context.Context) map[string][]string {
	headers := make(map[string][]string)
	for key, value := range context.Headers {
		headers[key] = append([]string{}, value...)
	}
	return headers
}

// GetAttackDetected constructs the DetectedAttack struct to be to the Agent
func GetAttackDetected(res InterceptorResult) *aikido_types.DetectedAttack {
	context := context.Get()
	return &aikido_types.DetectedAttack{
		Request: aikido_types.RequestInfo{
			Method:    *context.Method,
			IPAddress: *context.RemoteAddress,
			UserAgent: context.GetUserAgent(),
			URL:       context.URL,
			Headers:   getHeaders(context),
			Body:      context.GetBodyRaw(),
			Source:    context.Source,
			Route:     context.Route,
		},
		Attack: aikido_types.AttackDetails{
			Kind:      string(res.Kind),
			Operation: res.Operation,
			Module:    "Module",
			Blocked:   utils.IsBlockingEnabled(),
			Source:    res.Source,
			Path:      res.PathToPayload,
			Payload:   res.Payload,
			Metadata:  maps.Clone(res.Metadata),
			User:      utils.GetUserByID(context.GetUserID()),
		},
	}
}

func BuildAttackDetectedMessage(result InterceptorResult) string {
	return fmt.Sprintf("Aikido firewall has blocked %s: %s(...) originating from %s%s",
		GetDisplayNameForAttackKind(result.Kind),
		result.Operation,
		result.Source,
		html.EscapeString(result.PathToPayload))
}

func GetThrowAction(message string, code int) string {
	actionMap := map[string]any{
		"action":  "throw",
		"message": message,
		"code":    code,
	}
	actionJSON, err := json.Marshal(actionMap)
	if err != nil {
		return ""
	}
	return string(actionJSON)
}

func GetAttackDetectedAction(result InterceptorResult) string {
	return GetThrowAction(BuildAttackDetectedMessage(result), -1)
}

func ReportAttackDetected(res *InterceptorResult) string {
	if res == nil {
		return ""
	}

	go grpc.OnAttackDetected(GetAttackDetected(*res))
	return GetAttackDetectedAction(*res)
}
