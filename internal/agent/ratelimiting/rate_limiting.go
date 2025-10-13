package ratelimiting

import (
	"sync"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/log"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
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
	NumberOfRequestsPerWindow Queue
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
	IpCounts   map[string]*Counts
}

// Status represents the result of a rate limiting check
type Status struct {
	Block   bool
	Trigger string
}

var (
	// Map holds the current rate limiting state for each configured route
	Map = make(map[Key]*Value)

	// Mutex is used to sync access across the go routines
	Mutex sync.RWMutex

	// Channel and Ticker for the rate limiting background routine
	channel = make(chan struct{})
	ticker  = time.NewTicker(MinRateLimitingIntervalInMs * time.Millisecond)
)

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
				log.Warnf("More requests to substract (%d) than total number of requests (%d)!",
					numberOfRequestToSubstract, counts.TotalNumberOfRequests)
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
func advanceQueues() {
	Mutex.Lock()
	defer Mutex.Unlock()

	for _, endpoint := range Map {
		advanceQueuesForMap(&endpoint.Config, endpoint.UserCounts)
		advanceQueuesForMap(&endpoint.Config, endpoint.IpCounts)
	}
}

// Init initializes the rate limiting subsystem
func Init() {
	advanceQueues()
	utils.StartPollingRoutine(channel, ticker, advanceQueues)
}

// Uninit shuts down the rate limiting subsystem
func Uninit() {
	utils.StopPollingRoutine(channel)
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
func UpdateCounts(method string, route string, user string, ip string) {
	Mutex.Lock()
	defer Mutex.Unlock()

	rateLimitingData, exists := Map[Key{Method: method, Route: route}]
	if !exists {
		return
	}

	incrementRateLimitingCounts(rateLimitingData.UserCounts, user)
	incrementRateLimitingCounts(rateLimitingData.IpCounts, ip)
}

func isRateLimitingThresholdExceeded(config *Config, countsMap map[string]*Counts, key string) bool {
	counts, exists := countsMap[key]
	if !exists {
		return false
	}

	return counts.TotalNumberOfRequests >= config.MaxRequests
}

// GetStatus checks if a request should be rate limited based on user or IP
func GetStatus(method string, route string, user string, ip string) *Status {
	Mutex.RLock()
	defer Mutex.RUnlock()

	rateLimitingDataForRoute, exists := Map[Key{Method: method, Route: route}]
	if !exists {
		return &Status{Block: false}
	}

	if user != "" {
		// If the user exists, we only try to rate limit by user
		if isRateLimitingThresholdExceeded(&rateLimitingDataForRoute.Config, rateLimitingDataForRoute.UserCounts, user) {
			log.Infof("Rate limited request for user %s - %s %s - %v", user, method, route, rateLimitingDataForRoute.UserCounts[user])
			return &Status{Block: true, Trigger: "user"}
		}
	} else {
		// Otherwise, we rate limit by ip
		if isRateLimitingThresholdExceeded(&rateLimitingDataForRoute.Config, rateLimitingDataForRoute.IpCounts, ip) {
			log.Infof("Rate limited request for ip %s - %s %s - %v", ip, method, route, rateLimitingDataForRoute.IpCounts[ip])
			return &Status{Block: true, Trigger: "ip"}
		}
	}

	return &Status{Block: false}
}
