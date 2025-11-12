package ratelimiting

import (
	"log/slog"
	"sync"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/utils"
	"github.com/AikidoSec/firewall-go/internal/log"
)

const (
	MinRateLimitingIntervalInMs = 60000   // 1 minute
	MaxRateLimitingIntervalInMs = 3600000 // 1 hour
)

type Config struct {
	MaxRequests         int
	WindowSizeInMinutes int
}

// Counts tracks rate limiting counts for a specific entity (user or IP)
type Counts struct {
	NumberOfRequestsPerWindow queue
	TotalNumberOfRequests     int
}

// Key identifies a specific endpoint for rate limiting
type Key struct {
	Method string
	Route  string
}

// Value holds the rate limiting configuration and counts for an endpoint
type Value struct {
	Config     Config
	UserCounts map[string]*Counts
	IPCounts   map[string]*Counts
}

// Status represents the result of a rate limiting check
type Status struct {
	Block   bool
	Trigger string
}

type RateLimiter struct {
	// rateLimitingMap holds the current rate limiting state for each configured route
	rateLimitingMap map[Key]*Value

	mu sync.RWMutex

	// Channel and Ticker for the rate limiting background routine
	channel chan struct{}
	ticker  *time.Ticker
}

func New() *RateLimiter {
	return &RateLimiter{
		rateLimitingMap: make(map[Key]*Value),
		channel:         make(chan struct{}),
		ticker:          time.NewTicker(MinRateLimitingIntervalInMs * time.Millisecond),
	}
}

func advanceQueuesForMap(config *Config, countsMap map[string]*Counts) {
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

func incrementRateLimitingCounts(m map[string]*Counts, key string) {
	if key == "" {
		return
	}

	rateLimitingData, exists := m[key]
	if !exists {
		rateLimitingData = &Counts{}
		m[key] = rateLimitingData
	}

	rateLimitingData.TotalNumberOfRequests += 1
	rateLimitingData.NumberOfRequestsPerWindow.IncrementLast()
}

// UpdateCounts updates the rate limiting counts for a given route, user, and IP
func (rl *RateLimiter) UpdateCounts(method string, route string, user string, ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rateLimitingData, exists := rl.rateLimitingMap[Key{Method: method, Route: route}]
	if !exists {
		return
	}

	incrementRateLimitingCounts(rateLimitingData.UserCounts, user)
	incrementRateLimitingCounts(rateLimitingData.IPCounts, ip)
}

func isRateLimitingThresholdExceeded(config *Config, countsMap map[string]*Counts, key string) bool {
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

	rateLimitingDataForRoute, exists := rl.rateLimitingMap[Key{Method: method, Route: route}]
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

	updatedEndpoints := map[Key]bool{}

	for _, newEndpointConfig := range endpoints {
		k := Key{Method: newEndpointConfig.Method, Route: newEndpointConfig.Route}
		updatedEndpoints[k] = true

		rateLimitingData, exists := rl.rateLimitingMap[k]
		if exists {
			if rateLimitingData.Config.MaxRequests == newEndpointConfig.RateLimiting.MaxRequests &&
				rateLimitingData.Config.WindowSizeInMinutes == millisecondsToMinutes(newEndpointConfig.RateLimiting.WindowSizeInMS) {
				log.Debug("New rate limiting endpoint config is the same", slog.Any("config", newEndpointConfig))
				continue
			}

			log.Info("Rate limiting endpoint config has changed", slog.Any("config", newEndpointConfig))
			delete(rl.rateLimitingMap, k)
		}

		if !newEndpointConfig.RateLimiting.Enabled {
			log.Info("Got new rate limiting endpoint config, but is disabled", slog.Any("config", newEndpointConfig))
			continue
		}

		if newEndpointConfig.RateLimiting.WindowSizeInMS < MinRateLimitingIntervalInMs ||
			newEndpointConfig.RateLimiting.WindowSizeInMS > MaxRateLimitingIntervalInMs {
			log.Warn("Got new rate limiting endpoint config, but WindowSizeInMS is invalid", slog.Any("config", newEndpointConfig))
			continue
		}

		log.Info("Got new rate limiting endpoint config and storing to map", slog.Any("config", newEndpointConfig))
		rl.rateLimitingMap[k] = &Value{
			Config: Config{
				MaxRequests:         newEndpointConfig.RateLimiting.MaxRequests,
				WindowSizeInMinutes: millisecondsToMinutes(newEndpointConfig.RateLimiting.WindowSizeInMS),
			},
			UserCounts: make(map[string]*Counts),
			IPCounts:   make(map[string]*Counts),
		}
	}

	for k := range rl.rateLimitingMap {
		_, exists := updatedEndpoints[k]
		if !exists {
			log.Info("Removed rate limiting entry as it is no longer part of the config", slog.Any("endpoint", k))
			delete(rl.rateLimitingMap, k)
		}
	}
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
