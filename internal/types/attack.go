package types

import "encoding/json"

type Kind string

const (
	Sql_injection   Kind = "sql_injection"
	Shell_injection Kind = "shell_injection"
	Path_traversal  Kind = "path_traversal"
	Ssrf            Kind = "ssrf"
)

func GetDisplayNameForAttackKind(kind Kind) string {
	switch kind {
	case Sql_injection:
		return "an SQL injection"
	case Path_traversal:
		return "a path traversal attack"
	case Ssrf:
		return "a server-side request forgery"
	default:
		return "unknown attack type"
	}
}

type InterceptorResult struct {
	Kind          Kind
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
