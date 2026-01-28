package aikido_types

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
	Kind            OperationKind   `json:"kind"`
	Total           int             `json:"total"`
	AttacksDetected AttacksDetected `json:"attacksDetected"`
}
