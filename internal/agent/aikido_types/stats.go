package aikido_types

type MonitoredSinkTimings struct {
	AttacksDetected       AttacksDetected
	InterceptorThrewError int
	WithoutContext        int
	Total                 int
	Timings               []int64
}
