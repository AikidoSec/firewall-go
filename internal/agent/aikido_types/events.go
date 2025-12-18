package aikido_types

type Hostname struct {
	URL  string `json:"hostname"`
	Port uint32 `json:"port,omitempty"`
	Hits uint64 `json:"hits"`
}

type Route struct {
	Path    string   `json:"path"`
	Method  string   `json:"method"`
	Hits    int64    `json:"hits"`
	APISpec *APISpec `json:"apispec"`
}

type User struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	LastIpAddress string `json:"lastIpAddress"`
	FirstSeenAt   int64  `json:"firstSeenAt"`
	LastSeenAt    int64  `json:"lastSeenAt"`
}

type AttacksDetected struct {
	Total   int `json:"total"`
	Blocked int `json:"blocked"`
}

type CompressedTiming struct {
	AverageInMS  float64            `json:"averageInMS"`
	Percentiles  map[string]float64 `json:"percentiles"`
	CompressedAt int64              `json:"compressedAt"`
}

type MonitoredSinkStats struct {
	AttacksDetected       AttacksDetected    `json:"attacksDetected"`
	InterceptorThrewError int                `json:"interceptorThrewError"`
	WithoutContext        int                `json:"withoutContext"`
	Total                 int                `json:"total"`
	CompressedTimings     []CompressedTiming `json:"compressedTimings"`
}

type Requests struct {
	Total           int             `json:"total"`
	Aborted         int             `json:"aborted"`
	AttacksDetected AttacksDetected `json:"attacksDetected"`
	RateLimited     int             `json:"rateLimited"`
}

type Stats struct {
	Sinks     map[string]MonitoredSinkStats `json:"sinks"`
	StartedAt int64                         `json:"startedAt"`
	EndedAt   int64                         `json:"endedAt"`
	Requests  Requests                      `json:"requests"`
}

type RequestInfo struct {
	Method    string `json:"method"`
	IPAddress string `json:"ipAddress"`
	UserAgent string `json:"userAgent"`
	URL       string `json:"url"`
	Source    string `json:"source"`
	Route     string `json:"route"`
}

type AttackDetails struct {
	Kind      string            `json:"kind"`
	Operation string            `json:"operation"`
	Module    string            `json:"module"`
	Blocked   bool              `json:"blocked"`
	Source    string            `json:"source"`
	Path      string            `json:"path"`
	Stack     string            `json:"stack"`
	Payload   string            `json:"payload"`
	Metadata  map[string]string `json:"metadata"`
	User      *User             `json:"user"`
}
