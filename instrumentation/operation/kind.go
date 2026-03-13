package operation

// Kind identifies the type of operation being tracked.
type Kind string

const (
	KindSQL          Kind = "sql_op"
	KindNoSQL        Kind = "nosql_op"
	KindOutgoingHTTP Kind = "outgoing_http_op"
	KindFileSystem   Kind = "fs_op"
	KindExec         Kind = "exec_op"
	KindDeserialize  Kind = "deserialize_op"
	KindAI           Kind = "ai_op"
)
