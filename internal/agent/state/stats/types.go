package stats

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

type Snapshot struct {
	Operations  map[string]OperationStats `json:"operations"`
	StartedAt   int64                     `json:"startedAt"`
	EndedAt     int64                     `json:"endedAt"`
	Requests    Requests                  `json:"requests"`
	IPAddresses IPAddressBreakdown        `json:"ipAddresses"`
	UserAgents  UserAgentBreakdown        `json:"userAgents"`
}

type IPAddressBreakdown struct {
	Breakdown map[string]int `json:"breakdown"`
}

type UserAgentBreakdown struct {
	Breakdown map[string]int `json:"breakdown"`
}

type AttacksDetected struct {
	Total   int `json:"total"`
	Blocked int `json:"blocked"`
}

type Requests struct {
	Total           int             `json:"total"`
	Aborted         int             `json:"aborted"`
	AttacksDetected AttacksDetected `json:"attacksDetected"`
	RateLimited     int             `json:"rateLimited"`
}
