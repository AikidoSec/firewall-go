package rate_limiting

type RateLimitingConfig struct {
	MaxRequests         int
	WindowSizeInMinutes int
}

type RateLimitingCounts struct {
	NumberOfRequestsPerWindow Queue
	TotalNumberOfRequests     int
}

type RateLimitingKey struct {
	Method string
	Route  string
}

type RateLimitingValue struct {
	Config     RateLimitingConfig
	UserCounts map[string]*RateLimitingCounts
	IpCounts   map[string]*RateLimitingCounts
}

type RateLimitingStatus struct {
	Block   bool
	Trigger string
}
