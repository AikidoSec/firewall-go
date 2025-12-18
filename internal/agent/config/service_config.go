package config

import (
	"log/slog"
	"regexp"
	"sync"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/AikidoSec/firewall-go/internal/agent/ipaddr"
	"github.com/AikidoSec/firewall-go/internal/log"
)

var (
	serviceConfig      ServiceConfigData
	serviceConfigMutex sync.RWMutex
)

type RateLimiting struct {
	Enabled        bool
	MaxRequests    int
	WindowSizeInMS int
}

type EndpointKey struct {
	Method string
	Route  string
}

type Endpoint struct {
	Method             string                    `json:"method"`
	Route              string                    `json:"route"`
	ForceProtectionOff bool                      `json:"forceProtectionOff"`
	Graphql            any                       `json:"graphql"`
	AllowedIPAddresses ipaddr.MatchList          `json:"allowedIPAddresses"`
	RateLimiting       aikido_types.RateLimiting `json:"rateLimiting"`
}

type ServiceConfigData struct {
	ConfigUpdatedAt   time.Time
	Endpoints         []Endpoint
	BlockedUserIDs    map[string]bool
	BypassedIPs       ipaddr.MatchList
	AllowedIPs        map[string]ipaddr.MatchList
	BlockedIPs        map[string]ipaddr.MatchList
	BlockedUserAgents *regexp.Regexp
	Block             bool
}

func setServiceConfig(cloudConfigFromAgent *aikido_types.CloudConfigData, listsConfig *aikido_types.ListsConfigData) {
	if cloudConfigFromAgent == nil {
		return
	}

	serviceConfigMutex.Lock()
	defer serviceConfigMutex.Unlock()

	serviceConfig.ConfigUpdatedAt = time.UnixMilli(cloudConfigFromAgent.ConfigUpdatedAt)

	var endpoints []Endpoint
	for _, ep := range cloudConfigFromAgent.Endpoints {
		endpoints = append(endpoints, Endpoint{
			Method:             ep.Method,
			Route:              ep.Route,
			ForceProtectionOff: ep.ForceProtectionOff,
			AllowedIPAddresses: ipaddr.BuildMatchList("allowedIPs", "allowed", ep.AllowedIPAddresses),
			RateLimiting: aikido_types.RateLimiting{
				Enabled: ep.RateLimiting.Enabled,
			},
		})
	}
	serviceConfig.Endpoints = endpoints

	serviceConfig.BlockedUserIDs = map[string]bool{}
	for _, userID := range cloudConfigFromAgent.BlockedUserIds {
		serviceConfig.BlockedUserIDs[userID] = true
	}

	serviceConfig.BypassedIPs = ipaddr.BuildMatchList("bypassedIPs", "bypassed", cloudConfigFromAgent.BypassedIPs)

	if cloudConfigFromAgent.Block == nil {
		globals.AikidoConfig.ConfigMutex.Lock()
		serviceConfig.Block = globals.AikidoConfig.Blocking
		globals.AikidoConfig.ConfigMutex.Unlock()
	} else {
		serviceConfig.Block = *cloudConfigFromAgent.Block
	}

	if listsConfig != nil {
		serviceConfig.AllowedIPs = map[string]ipaddr.MatchList{}
		for _, ipAllowlist := range listsConfig.AllowedIPAddresses {
			if len(ipAllowlist.IPs) == 0 {
				continue
			}

			serviceConfig.AllowedIPs[ipAllowlist.Source] = ipaddr.BuildMatchList(
				ipAllowlist.Source,
				ipAllowlist.Description,
				ipAllowlist.IPs,
			)
		}

		serviceConfig.BlockedIPs = map[string]ipaddr.MatchList{}
		for _, ipBlocklist := range listsConfig.BlockedIPAddresses {
			serviceConfig.BlockedIPs[ipBlocklist.Source] = ipaddr.BuildMatchList(
				ipBlocklist.Source,
				ipBlocklist.Description,
				ipBlocklist.IPs,
			)
		}

		if listsConfig.BlockedUserAgents != "" {
			serviceConfig.BlockedUserAgents, _ = regexp.Compile("(?i)" + listsConfig.BlockedUserAgents)
		} else {
			serviceConfig.BlockedUserAgents = nil
		}
	}
}

func UpdateServiceConfig(cloudConfig *aikido_types.CloudConfigData, blockListConfig *aikido_types.ListsConfigData) {
	log.Debug("Got cloud config", slog.Any("config", cloudConfig))
	setServiceConfig(cloudConfig, blockListConfig)
}

var CollectAPISchema bool

func GetCloudConfigUpdatedAt() time.Time {
	serviceConfigMutex.RLock()
	defer serviceConfigMutex.RUnlock()

	return serviceConfig.ConfigUpdatedAt
}

// IsIPBlocked function checks the cloud config mutex for blocked IP addresses.
func IsIPBlocked(ip string) (bool, string) {
	serviceConfigMutex.RLock()
	defer serviceConfigMutex.RUnlock()

	ipAddress, err := ipaddr.Parse(ip)
	if err != nil {
		log.Info("Invalid ip address", slog.String("ip", ip))
		return false, ""
	}

	for _, ipBlocklist := range serviceConfig.BlockedIPs {
		if ipBlocklist.Matches(ipAddress) {
			return true, ipBlocklist.Description
		}
	}

	return false, ""
}

// IsIPAllowed checks that the IP is allowed if the global allowed IP list is set.
// Private/local IP addresses are always allowed, even when an allow list is configured.
func IsIPAllowed(ip string) bool {
	serviceConfigMutex.RLock()
	defer serviceConfigMutex.RUnlock()

	if len(serviceConfig.AllowedIPs) == 0 {
		return true
	}

	// Always allow private/local IP addresses (matches Node.js behavior)
	if ipaddr.IsPrivateIP(ip) {
		return true
	}

	ipAddress, err := ipaddr.Parse(ip)
	if err != nil {
		log.Info("Invalid ip address", slog.String("ip", ip))
		return false
	}

	for _, ipAllowlist := range serviceConfig.AllowedIPs {
		if ipAllowlist.Matches(ipAddress) {
			return true
		}
	}

	return false
}

// IsUserAgentBlocked returns true if we block (e.g. bot blocking), and a string with the reason why.
func IsUserAgentBlocked(userAgent string) (bool, string) {
	serviceConfigMutex.RLock()
	defer serviceConfigMutex.RUnlock()

	if serviceConfig.BlockedUserAgents == nil {
		return false, ""
	}

	if serviceConfig.BlockedUserAgents.MatchString(userAgent) {
		return true, "bot detection"
	}

	return false, ""
}

func IsUserBlocked(userID string) bool {
	serviceConfigMutex.RLock()
	defer serviceConfigMutex.RUnlock()

	return keyExists(serviceConfig.BlockedUserIDs, userID)
}

func SetUserBlocked(userID string) {
	serviceConfigMutex.Lock()
	defer serviceConfigMutex.Unlock()

	if serviceConfig.BlockedUserIDs == nil {
		serviceConfig.BlockedUserIDs = map[string]bool{}
	}

	serviceConfig.BlockedUserIDs[userID] = true
}

func IsIPBypassed(ip string) bool {
	serviceConfigMutex.RLock()
	defer serviceConfigMutex.RUnlock()

	ipAddress, err := ipaddr.Parse(ip)
	if err != nil {
		log.Debug("Invalid ip address", slog.String("ip", ip))
		return false
	}

	return serviceConfig.BypassedIPs.Matches(ipAddress)
}

func GetEndpoints() []Endpoint {
	serviceConfigMutex.RLock()
	defer serviceConfigMutex.RUnlock()

	return serviceConfig.Endpoints
}

func keyExists[K comparable, V any](m map[K]V, key K) bool {
	_, exists := m[key]
	return exists
}
