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
