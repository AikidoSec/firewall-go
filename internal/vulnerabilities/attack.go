package vulnerabilities

import (
	"encoding/json"
	"fmt"

	"github.com/AikidoSec/firewall-go/internal/context"
	"github.com/AikidoSec/firewall-go/internal/grpc"
	"github.com/AikidoSec/firewall-go/internal/helpers"
	"github.com/AikidoSec/zen-internals-agent/ipc/protos"
	"github.com/AikidoSec/zen-internals-agent/utils"
)

type AttackKind string

const (
	KindSqlInjection  AttackKind = "sql_injection"
	KindPathTraversal AttackKind = "path_traversal"
	KindSSRF          AttackKind = "ssrf"
)

func GetDisplayNameForAttackKind(kind AttackKind) string {
	switch kind {
	case KindSqlInjection:
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

// Convert metadata map to protobuf structure to be sent via gRPC to the Agent
func GetMetadataProto(metadata map[string]string) []*protos.Metadata {
	var metadataProto []*protos.Metadata
	for key, value := range metadata {
		metadataProto = append(metadataProto, &protos.Metadata{Key: key, Value: value})
	}
	return metadataProto
}

// Convert headers map to protobuf structure to be sent via gRPC to the Agent
func GetHeadersProto(context *context.Context) []*protos.Header {
	var headersProto []*protos.Header
	for key, value := range context.Headers {
		// Only report first header :
		headersProto = append(headersProto, &protos.Header{Key: key, Value: value[0]})
	}
	return headersProto
}

// Construct the AttackDetected protobuf structure to be sent via gRPC to the Agent
func GetAttackDetectedProto(res InterceptorResult) *protos.AttackDetected {
	context := context.Get()
	return &protos.AttackDetected{
		Request: &protos.Request{
			Method:    *context.Method,
			IpAddress: *context.RemoteAddress,
			UserAgent: context.GetUserAgent(),
			Url:       context.URL,
			Headers:   GetHeadersProto(context),
			Body:      context.GetBodyRaw(),
			Source:    context.Source,
			Route:     context.Route,
		},
		Attack: &protos.Attack{
			Kind:      string(res.Kind),
			Operation: res.Operation,
			Module:    "Module",
			Blocked:   utils.IsBlockingEnabled(),
			Source:    res.Source,
			Path:      res.PathToPayload,
			Payload:   res.Payload,
			Metadata:  GetMetadataProto(res.Metadata),
			UserId:    context.GetUserId(),
		},
	}
}

func BuildAttackDetectedMessage(result InterceptorResult) string {
	return fmt.Sprintf("Aikido firewall has blocked %s: %s(...) originating from %s%s",
		GetDisplayNameForAttackKind(result.Kind),
		result.Operation,
		result.Source,
		helpers.EscapeHTML(result.PathToPayload))
}

func GetThrowAction(message string, code int) string {
	actionMap := map[string]interface{}{
		"action":  "throw",
		"message": message,
		"code":    code,
	}
	actionJson, err := json.Marshal(actionMap)
	if err != nil {
		return ""
	}
	return string(actionJson)
}

func GetAttackDetectedAction(result InterceptorResult) string {
	return GetThrowAction(BuildAttackDetectedMessage(result), -1)
}

func ReportAttackDetected(res *InterceptorResult) string {
	if res == nil {
		return ""
	}

	go grpc.OnAttackDetected(GetAttackDetectedProto(*res))
	return GetAttackDetectedAction(*res)
}
