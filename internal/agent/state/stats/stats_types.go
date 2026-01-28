package stats

import (
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
)

type OperationKind string

const (
	OperationKindSQL          OperationKind = "sql_op"
	OperationKindNoSQL        OperationKind = "nosql_op"
	OperationKindOutgoingHTTP OperationKind = "outgoing_http_op"
	OperationKindFileSystem   OperationKind = "fs_op"
	OperationKindExec         OperationKind = "exec_op"
	OperationKindDeserialize  OperationKind = "deserialize_op"
	OperationKindAI           OperationKind = "ai_op"
)

type OperationStats struct {
	Kind            OperationKind                `json:"kind"`
	Total           int                          `json:"total"`
	AttacksDetected aikido_types.AttacksDetected `json:"attacksDetected"`
}

type Data struct {
	Operations map[string]OperationStats `json:"operations"`
	StartedAt  int64                     `json:"startedAt"`
	EndedAt    int64                     `json:"endedAt"`
	Requests   aikido_types.Requests     `json:"requests"`
}
