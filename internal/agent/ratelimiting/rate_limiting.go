package ratelimiting

import (
	"log/slog"
	"sync"
	"time"

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
	MaxRequests         int
	WindowSizeInMinutes int
}

// endpointKey identifies a specific endpoint for rate limiting
type endpointKey struct {
	Method string
	Route  string
}

// endpointData holds the rate limiting configuration and counts for an endpoint
type endpointData struct {
	Config     rateLimitConfig
	UserCounts map[string]*slidingwindow.Window
	IPCounts   map[string]*slidingwindow.Window
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

// getOrCreateCounts gets existing counts or creates new ones
func getOrCreateCounts(m map[string]*slidingwindow.Window, key string, windowSizeSeconds int64, maxRequests int) *slidingwindow.Window {
	if key == "" {
		return nil
	}

	if _, ok := m[key]; !ok {
		m[key] = slidingwindow.New(windowSizeSeconds, maxRequests)
	}

	return m[key]
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
	maxRequests := rateLimitingDataForRoute.Config.MaxRequests
	windowSizeSeconds := int64(rateLimitingDataForRoute.Config.WindowSizeInMinutes * 60)

	if user != "" {
		// If the user exists, we only try to rate limit by user
		if counts := getOrCreateCounts(rateLimitingDataForRoute.UserCounts, user, windowSizeSeconds, maxRequests); counts != nil {
			if !counts.TryRecord(now) {
				log.Info("Rate limited request for user",
					slog.String("user", user),
					slog.String("method", method),
					slog.String("route", route),
					slog.Int("count", counts.Count(now)))

				return &Status{Block: true, Trigger: "user"}
			}
		}
	} else if ip != "" {
		// Otherwise, we rate limit by ip

		if counts := getOrCreateCounts(rateLimitingDataForRoute.IPCounts, ip, windowSizeSeconds, maxRequests); counts != nil {
			if !counts.TryRecord(now) {
				log.Info("Rate limited request for ip",
					slog.String("ip", ip),
					slog.String("method", method),
					slog.String("route", route),
					slog.Int("count", counts.Count(now)))

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

	for _, endpoint := range rl.rateLimitingMap {
		cleanupInactiveMap(endpoint.UserCounts, now)
		cleanupInactiveMap(endpoint.IPCounts, now)
	}
}

func cleanupInactiveMap(m map[string]*slidingwindow.Window, now int64) {
	keysToDelete := make([]string, 0)
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
			UserCounts: make(map[string]*slidingwindow.Window),
			IPCounts:   make(map[string]*slidingwindow.Window),
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
