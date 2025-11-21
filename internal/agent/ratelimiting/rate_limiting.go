package ratelimiting

import (
	"log/slog"
	"sync"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/endpoints"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
	"github.com/AikidoSec/firewall-go/internal/log"
)

const (
	MinRateLimitingIntervalInMs = 60000   // 1 minute
	MaxRateLimitingIntervalInMs = 3600000 // 1 hour
)

type rateLimitConfig struct {
	MaxRequests         int
	WindowSizeInMinutes int
	WindowSizeInMS      int // Store original window size in milliseconds for rate calculation
}

// entityCounts tracks rate limiting counts for a specific entity (user or IP)
type entityCounts struct {
	NumberOfRequestsPerWindow queue
	TotalNumberOfRequests     int
}

// endpointKey identifies a specific endpoint for rate limiting
type endpointKey struct {
	Method string
	Route  string
}

// endpointData holds the rate limiting configuration and counts for an endpoint
type endpointData struct {
	Config     rateLimitConfig
	UserCounts map[string]*entityCounts
	IPCounts   map[string]*entityCounts
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
		ticker:          time.NewTicker(MinRateLimitingIntervalInMs * time.Millisecond),
	}
}

func advanceQueuesForMap(config *rateLimitConfig, countsMap map[string]*entityCounts) {
	for _, counts := range countsMap {
		if config.WindowSizeInMinutes <= counts.NumberOfRequestsPerWindow.Length() {
			// Sliding window is moving, need to substract the entry that goes out of the window
			// Ex: if the window is set to 10 minutes, when another minute passes,
			//     need to remove the number of requests from the entry of 11 minutes ago

			// Get the number of requests for the entry that just dropped out of the sliding window
			numberOfRequestToSubstract := counts.NumberOfRequestsPerWindow.Pop()
			if counts.TotalNumberOfRequests < numberOfRequestToSubstract {
				// This should never happen, but better to have a check in place
				log.Warn("More requests to subtract than total number of requests",
					slog.Int("to_subtract", numberOfRequestToSubstract),
					slog.Int("total", counts.TotalNumberOfRequests))
			} else {
				// Remove the number of requests for the entry that just dropped out of the sliding window from total
				counts.TotalNumberOfRequests -= numberOfRequestToSubstract
			}
		}

		// Create a new entry in queue for the current minute
		counts.NumberOfRequestsPerWindow.Push(0)
	}
}

// advanceQueues moves the sliding window forward by one time unit
func (rl *RateLimiter) advanceQueues() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	for _, endpoint := range rl.rateLimitingMap {
		advanceQueuesForMap(&endpoint.Config, endpoint.UserCounts)
		advanceQueuesForMap(&endpoint.Config, endpoint.IPCounts)
	}
}

// Init initializes the rate limiting subsystem
func (rl *RateLimiter) Init() {
	rl.advanceQueues()
	utils.StartPollingRoutine(rl.channel, rl.ticker, rl.advanceQueues)
}

// Uninit shuts down the rate limiting subsystem
func (rl *RateLimiter) Uninit() {
	utils.StopPollingRoutine(rl.channel)
}

func incrementRateLimitingCounts(m map[string]*entityCounts, key string) {
	if key == "" {
		return
	}

	rateLimitingData, exists := m[key]
	if !exists {
		rateLimitingData = &entityCounts{}
		m[key] = rateLimitingData
	}

	rateLimitingData.TotalNumberOfRequests += 1
	rateLimitingData.NumberOfRequestsPerWindow.IncrementLast()
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

// UpdateCounts updates the rate limiting counts for a given route, user, and IP
func (rl *RateLimiter) UpdateCounts(method string, route string, user string, ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	matchingKey := rl.findMatchingRateLimitEndpoint(method, route)
	if matchingKey == nil {
		return
	}

	rateLimitingData, exists := rl.rateLimitingMap[*matchingKey]
	if !exists {
		return
	}

	incrementRateLimitingCounts(rateLimitingData.UserCounts, user)
	incrementRateLimitingCounts(rateLimitingData.IPCounts, ip)
}

func isRateLimitingThresholdExceeded(config *rateLimitConfig, countsMap map[string]*entityCounts, key string) bool {
	counts, exists := countsMap[key]
	if !exists {
		return false
	}

	return counts.TotalNumberOfRequests >= config.MaxRequests
}

// GetStatus checks if a request should be rate limited based on user or IP
func (rl *RateLimiter) GetStatus(method string, route string, user string, ip string) *Status {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	matchingKey := rl.findMatchingRateLimitEndpoint(method, route)
	if matchingKey == nil {
		return &Status{Block: false}
	}

	rateLimitingDataForRoute, exists := rl.rateLimitingMap[*matchingKey]
	if !exists {
		return &Status{Block: false}
	}

	if user != "" {
		// If the user exists, we only try to rate limit by user
		if isRateLimitingThresholdExceeded(&rateLimitingDataForRoute.Config, rateLimitingDataForRoute.UserCounts, user) {
			log.Info("Rate limited request for user",
				slog.String("user", user),
				slog.String("method", method),
				slog.String("route", route),
				slog.Any("counts", rateLimitingDataForRoute.UserCounts[user]))
			return &Status{Block: true, Trigger: "user"}
		}
	} else {
		// Otherwise, we rate limit by ip
		if isRateLimitingThresholdExceeded(&rateLimitingDataForRoute.Config, rateLimitingDataForRoute.IPCounts, ip) {
			log.Info("Rate limited request for ip",
				slog.String("ip", ip),
				slog.String("method", method),
				slog.String("route", route),
				slog.Any("counts", rateLimitingDataForRoute.IPCounts[ip]))
			return &Status{Block: true, Trigger: "ip"}
		}
	}

	return &Status{Block: false}
}

func millisecondsToMinutes(ms int) int {
	duration := time.Duration(ms) * time.Millisecond
	return int(duration.Minutes())
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
		if endpoint.RateLimiting.WindowSizeInMS < MinRateLimitingIntervalInMs ||
			endpoint.RateLimiting.WindowSizeInMS > MaxRateLimitingIntervalInMs {
			log.Warn("Invalid rate limiting WindowSizeInMS, skipping", slog.Any("endpoint", endpoint))
			continue
		}

		k := endpointKey{Method: endpoint.Method, Route: endpoint.Route}
		newConfig := rateLimitConfig{
			MaxRequests:         endpoint.RateLimiting.MaxRequests,
			WindowSizeInMinutes: millisecondsToMinutes(endpoint.RateLimiting.WindowSizeInMS),
			WindowSizeInMS:      endpoint.RateLimiting.WindowSizeInMS,
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
			Config:     newConfig,
			UserCounts: make(map[string]*entityCounts),
			IPCounts:   make(map[string]*entityCounts),
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

func GetStatus(method string, route string, user string, ip string) *Status {
	return globalRateLimiter.GetStatus(method, route, user, ip)
}

func UpdateConfig(endpoints []EndpointConfig) {
	globalRateLimiter.UpdateConfig(endpoints)
}

func UpdateCounts(method string, route string, user string, ip string) {
	globalRateLimiter.UpdateCounts(method, route, user, ip)
}
