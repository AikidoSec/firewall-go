package rate_limiting

import "sync"

// Rate limiting map, which holds the current rate limiting state for each configured route
var RateLimitingMap = make(map[RateLimitingKey]*RateLimitingValue)

// Rate limiting mutex used to sync access across the go routines
var RateLimitingMutex sync.RWMutex
