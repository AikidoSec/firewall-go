package ratelimiting

import (
	"log/slog"
	"sync"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/utils"
	"github.com/AikidoSec/firewall-go/internal/log"
)

const (
	minRateLimitingWindowInMs = 60000   // 1 minute
	maxRateLimitingWindowInMs = 3600000 // 1 hour
	inactiveCleanupInterval   = 5 * time.Minute
	inactivityThreshold       = 1 * time.Hour
)

type rateLimitConfig struct {
	MaxRequests         int
	WindowSizeInMinutes int
}

// entityCounts tracks rate limiting counts for a specific entity (user or IP)
type entityCounts struct {
	requestTimestamps []int64 // Unix timestamps in seconds
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

// cleanOldTimestamps removes timestamps older than windowStart from the slice
func cleanOldTimestamps(counts *entityCounts, windowStart int64) {
	i := 0
	for i < len(counts.requestTimestamps) && counts.requestTimestamps[i] < windowStart {
		i++
	}
	counts.requestTimestamps = counts.requestTimestamps[i:]
}

// getOrCreateCounts gets existing counts or creates new ones
func getOrCreateCounts(m map[string]*entityCounts, key string) *entityCounts {
	if key == "" {
		return nil
	}

	counts, exists := m[key]
	if !exists {
		counts = &entityCounts{
			requestTimestamps: make([]int64, 0),
		}
		m[key] = counts
	}
	return counts
}

// updateEntityCounts updates the counts for a single entity (user or IP)
func updateEntityCounts(m map[string]*entityCounts, key string, windowStart, now int64) {
	counts := getOrCreateCounts(m, key)
	if counts != nil {
		cleanOldTimestamps(counts, windowStart)
		counts.requestTimestamps = append(counts.requestTimestamps, now)
	}
}

// ShouldRateLimitRequest checks if a request should be rate limited based on user or IP
func (rl *RateLimiter) ShouldRateLimitRequest(method string, route string, user string, ip string) *Status {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rateLimitingDataForRoute, exists := rl.rateLimitingMap[endpointKey{Method: method, Route: route}]
	if !exists {
		return &Status{Block: false}
	}

	now := time.Now().Unix()
	windowStart := now - int64(rateLimitingDataForRoute.Config.WindowSizeInMinutes*60)

	if user != "" {
		// If the user exists, we only try to rate limit by user

		updateEntityCounts(rateLimitingDataForRoute.UserCounts, user, windowStart, now)
		if counts, exists := rateLimitingDataForRoute.UserCounts[user]; exists {
			cleanOldTimestamps(counts, windowStart)

			if len(counts.requestTimestamps) >= rateLimitingDataForRoute.Config.MaxRequests {
				log.Info("Rate limited request for user",
					slog.String("user", user),
					slog.String("method", method),
					slog.String("route", route),
					slog.Int("count", len(counts.requestTimestamps)))
				return &Status{Block: true, Trigger: "user"}
			}
		}
	} else if ip != "" {
		// Otherwise, we rate limit by ip

		updateEntityCounts(rateLimitingDataForRoute.IPCounts, ip, windowStart, now)
		if counts, exists := rateLimitingDataForRoute.IPCounts[ip]; exists {
			cleanOldTimestamps(counts, windowStart)

			if len(counts.requestTimestamps) >= rateLimitingDataForRoute.Config.MaxRequests {
				log.Info("Rate limited request for ip",
					slog.String("ip", ip),
					slog.String("method", method),
					slog.String("route", route),
					slog.Int("count", len(counts.requestTimestamps)))
				return &Status{Block: true, Trigger: "ip"}
			}
		}
	}

	return &Status{Block: false}
}

// cleanupInactive removes completely inactive users/IPs from the maps
func (rl *RateLimiter) cleanupInactive() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now().Unix()
	threshold := int64(inactivityThreshold.Seconds())

	for _, endpoint := range rl.rateLimitingMap {
		cleanupInactiveMap(endpoint.UserCounts, now, threshold)
		cleanupInactiveMap(endpoint.IPCounts, now, threshold)
	}
}

func cleanupInactiveMap(m map[string]*entityCounts, now, threshold int64) {
	keysToDelete := make([]string, 0)
	for key, counts := range m {
		if len(counts.requestTimestamps) == 0 {
			keysToDelete = append(keysToDelete, key)
			continue
		}
		// Check last timestamp
		lastRequest := counts.requestTimestamps[len(counts.requestTimestamps)-1]
		if now-lastRequest > threshold {
			keysToDelete = append(keysToDelete, key)
		}
	}
	// Delete after iteration to avoid modifying map during iteration
	for _, key := range keysToDelete {
		delete(m, key)
	}
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
		if endpoint.RateLimiting.WindowSizeInMS < minRateLimitingWindowInMs ||
			endpoint.RateLimiting.WindowSizeInMS > maxRateLimitingWindowInMs {
			log.Warn("Invalid rate limiting WindowSizeInMS, skipping", slog.Any("endpoint", endpoint))
			continue
		}

		k := endpointKey{Method: endpoint.Method, Route: endpoint.Route}
		newConfig := rateLimitConfig{
			MaxRequests:         endpoint.RateLimiting.MaxRequests,
			WindowSizeInMinutes: millisecondsToMinutes(endpoint.RateLimiting.WindowSizeInMS),
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

func ShouldRateLimitRequest(method string, route string, user string, ip string) *Status {
	return globalRateLimiter.ShouldRateLimitRequest(method, route, user, ip)
}

func UpdateConfig(endpoints []EndpointConfig) {
	globalRateLimiter.UpdateConfig(endpoints)
}
