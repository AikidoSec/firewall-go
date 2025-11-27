package ratelimiting

import (
	"log/slog"
	"sync"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/endpoints"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/slidingwindow"
)

const (
	minRateLimitingWindowInMs = 60000   // 1 minute
	maxRateLimitingWindowInMs = 3600000 // 1 hour
	inactiveCleanupInterval   = 5 * time.Minute
)

type rateLimitConfig struct {
	MaxRequests    int
	WindowSizeInMS int
}

// endpointKey identifies a specific endpoint for rate limiting
type endpointKey struct {
	Method string
	Route  string
}

type entityKind int

const (
	entityKindUser entityKind = iota
	entityKindIP
)

type entityKey struct {
	Kind  entityKind
	Value string
}

func (et entityKind) String() string {
	switch et {
	case entityKindUser:
		return "user"
	case entityKindIP:
		return "ip"
	default:
		return "unknown"
	}
}

// endpointData holds the rate limiting configuration and counts for an endpoint
type endpointData struct {
	Config rateLimitConfig
	Counts map[entityKey]*slidingwindow.Window
}

// Status represents the result of a rate limiting check
type Status struct {
	Block   bool
	Trigger string
}

type RateLimiter struct {
	// rateLimitingMap holds the current rate limiting state for each configured route
	rateLimitingMap map[endpointKey]*endpointData

	mu sync.RWMutex

	// Channel and Ticker for the rate limiting background routine
	channel chan struct{}
	ticker  *time.Ticker
}

func New() *RateLimiter {
	return &RateLimiter{
		rateLimitingMap: make(map[endpointKey]*endpointData),
		channel:         make(chan struct{}),
		ticker:          time.NewTicker(inactiveCleanupInterval),
	}
}

// Init initializes the rate limiting subsystem with periodic cleanup
func (rl *RateLimiter) Init() {
	utils.StartPollingRoutine(rl.channel, rl.ticker, rl.cleanupInactive)
}

// Uninit shuts down the rate limiting subsystem
func (rl *RateLimiter) Uninit() {
	utils.StopPollingRoutine(rl.channel)
}

func getOrCreateCounts(m map[entityKey]*slidingwindow.Window, key entityKey, windowSizeSeconds int64, maxRequests int) *slidingwindow.Window {
	if _, ok := m[key]; !ok {
		m[key] = slidingwindow.New(windowSizeSeconds, maxRequests)
	}

	return m[key]
}

// ShouldRateLimitRequest checks if a request should be rate limited based on user or IP
func (rl *RateLimiter) ShouldRateLimitRequest(method string, route string, user string, ip string) *Status {
	// Priority: user > ip
	if user != "" {
		return rl.checkEntity(method, route, entityKindUser, user)
	} else if ip != "" {
		return rl.checkEntity(method, route, entityKindIP, ip)
	}

	return &Status{Block: false}
}

func (rl *RateLimiter) checkEntity(method string, route string, kind entityKind, entityValue string) *Status {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	matchingKey := rl.findMatchingRateLimitEndpoint(method, route)
	if matchingKey == nil {
		return &Status{Block: false}
	}

	rateLimitingDataForRoute, exists := rl.rateLimitingMap[*matchingKey]
	if !exists {
		return &Status{Block: false}
	}

	now := time.Now().UnixMilli()
	maxRequests := rateLimitingDataForRoute.Config.MaxRequests

	key := entityKey{Kind: kind, Value: entityValue}
	counts := getOrCreateCounts(rateLimitingDataForRoute.Counts, key,
		int64(rateLimitingDataForRoute.Config.WindowSizeInMS), maxRequests)

	if counts == nil {
		return &Status{Block: false}
	}

	if !counts.TryRecord(now) {
		trigger := kind.String()

		log.Info("Rate limited request",
			slog.String(trigger, entityValue),
			slog.String("method", method),
			slog.String("route", route),
			slog.Int("count", counts.Count(now)))

		return &Status{Block: true, Trigger: trigger}
	}

	return &Status{Block: false}
}

// findMatchingRateLimitEndpoint finds the appropriate rate limiting endpoint for a given method and route.
// It uses [endpoints.FindMatches] to find all matching endpoints, then:
// 1. Checks for exact route match first
// 2. If no exact match, selects the most restrictive rate (lowest maxRequests / windowSizeInMS)
func (rl *RateLimiter) findMatchingRateLimitEndpoint(method string, route string) *endpointKey {
	var endpointList []aikido_types.Endpoint
	for key := range rl.rateLimitingMap {
		endpointList = append(endpointList, aikido_types.Endpoint{
			Method: key.Method,
			Route:  key.Route,
		})
	}

	matches := endpoints.FindMatches(endpointList, endpoints.RouteMetadata{
		Method: method,
		Route:  route,
	})

	if len(matches) == 0 {
		return nil
	}

	// Check for exact route match first ([endpoints.FindMatches] returns exact matches first)
	for _, match := range matches {
		if match.Route == route {
			key := endpointKey{Method: match.Method, Route: match.Route}
			return &key
		}
	}

	// No exact match found, find the most restrictive (lowest rate)
	var mostRestrictive *endpointKey
	var lowestRate float64

	for _, match := range matches {
		key := endpointKey{Method: match.Method, Route: match.Route}
		data := rl.rateLimitingMap[key]
		if data.Config.WindowSizeInMS == 0 {
			continue
		}

		rate := float64(data.Config.MaxRequests) / float64(data.Config.WindowSizeInMS)

		if mostRestrictive == nil || rate < lowestRate {
			mostRestrictive = &key
			lowestRate = rate
		}
	}

	return mostRestrictive
}

// cleanupInactive removes completely inactive users/IPs from the maps
func (rl *RateLimiter) cleanupInactive() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now().UnixMilli()

	for _, endpoint := range rl.rateLimitingMap {
		cleanupInactiveMap(endpoint.Counts, now)
	}
}

func cleanupInactiveMap(m map[entityKey]*slidingwindow.Window, now int64) {
	keysToDelete := make([]entityKey, 0)
	for key, counts := range m {
		if counts.Count(now) == 0 {
			keysToDelete = append(keysToDelete, key)
		}
	}

	// Delete after iteration to avoid modifying map during iteration
	for _, key := range keysToDelete {
		delete(m, key)
	}
}

// EndpointConfig represents the rate limiting configuration for an endpoint
type EndpointConfig struct {
	Method       string
	Route        string
	RateLimiting struct {
		Enabled        bool
		MaxRequests    int
		WindowSizeInMS int
	}
}

// UpdateConfig updates the rate limiting configuration from cloud endpoints
func (rl *RateLimiter) UpdateConfig(endpoints []EndpointConfig) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	newMap := make(map[endpointKey]*endpointData)

	for _, endpoint := range endpoints {
		if !endpoint.RateLimiting.Enabled {
			log.Debug("Skipping disabled rate limiting endpoint", slog.Any("endpoint", endpoint))
			continue
		}

		// Validate window size
		if endpoint.RateLimiting.WindowSizeInMS < minRateLimitingWindowInMs ||
			endpoint.RateLimiting.WindowSizeInMS > maxRateLimitingWindowInMs {
			log.Warn("Invalid rate limiting WindowSizeInMS, skipping", slog.Any("endpoint", endpoint))
			continue
		}

		k := endpointKey{Method: endpoint.Method, Route: endpoint.Route}
		newConfig := rateLimitConfig{
			MaxRequests:    endpoint.RateLimiting.MaxRequests,
			WindowSizeInMS: endpoint.RateLimiting.WindowSizeInMS,
		}

		// Check if we can preserve existing data
		if existingData, exists := rl.rateLimitingMap[k]; exists {
			if existingData.Config == newConfig {
				// Config unchanged, preserve data
				log.Debug("Rate limiting config unchanged, preserving data", slog.Any("config", endpoint))
				newMap[k] = existingData
				continue
			}
			log.Info("Rate limiting config changed, resetting data", slog.Any("config", endpoint))
		} else {
			log.Info("Adding new rate limiting endpoint", slog.Any("config", endpoint))
		}

		// Create new entry
		newMap[k] = &endpointData{
			Config: newConfig,
			Counts: make(map[entityKey]*slidingwindow.Window),
		}
	}

	for k := range rl.rateLimitingMap {
		if _, exists := newMap[k]; !exists {
			log.Info("Removing rate limiting endpoint", slog.Any("endpoint", k))
		}
	}

	// Replace the entire map
	rl.rateLimitingMap = newMap
}

// global instance
var globalRateLimiter = New()

func Init() {
	globalRateLimiter.Init()
}

func Uninit() {
	globalRateLimiter.Uninit()
}

func ShouldRateLimitRequest(method string, route string, user string, ip string) *Status {
	return globalRateLimiter.ShouldRateLimitRequest(method, route, user, ip)
}

func UpdateConfig(endpoints []EndpointConfig) {
	globalRateLimiter.UpdateConfig(endpoints)
}
