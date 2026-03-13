package stats

import (
	"github.com/AikidoSec/firewall-go/instrumentation/operation"
)

type OperationStats struct {
	Kind            operation.Kind  `json:"kind"`
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
