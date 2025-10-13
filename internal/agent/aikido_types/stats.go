package aikido_types

import "sync"

type MonitoredSinkTimings struct {
	AttacksDetected       AttacksDetected
	InterceptorThrewError int
	WithoutContext        int
	Total                 int
	Timings               []int64
}

type StatsDataType struct {
	StatsMutex sync.Mutex

	StartedAt       int64
	Requests        int
	RequestsAborted int
	Attacks         int
	AttacksBlocked  int

	MonitoredSinkTimings map[string]MonitoredSinkTimings
}
