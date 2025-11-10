package config

import (
	"log/slog"
	"regexp"
	"sync"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/seancfoley/ipaddress-go/ipaddr"
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

type EndpointData struct {
	ForceProtectionOff bool
	RateLimiting       RateLimiting
	AllowedIPAddresses map[string]bool
}

type EndpointKey struct {
	Method string
	Route  string
}

type IPBlockList struct {
	Description string
	TrieV4      *ipaddr.IPv4AddressTrie
	TrieV6      *ipaddr.IPv6AddressTrie
}

type ServiceConfigData struct {
	ConfigUpdatedAt   int64
	Endpoints         []aikido_types.Endpoint
	BlockedUserIDs    map[string]bool
	BypassedIPs       map[string]bool
	BlockedIPs        map[string]IPBlockList
	BlockedUserAgents *regexp.Regexp
	Block             bool
}

func buildIPBlocklist(name, description string, ipsList []string) IPBlockList {
	ipBlocklist := IPBlockList{
		Description: description,
		TrieV4:      &ipaddr.IPv4AddressTrie{},
		TrieV6:      &ipaddr.IPv6AddressTrie{},
	}

	for _, ip := range ipsList {
		ipAddress, err := ipaddr.NewIPAddressString(ip).ToAddress()
		if err != nil {
			log.Info("Invalid address", slog.String("name", name), slog.String("ip", ip))
			continue
		}

		if ipAddress.IsIPv4() {
			ipBlocklist.TrieV4.Add(ipAddress.ToIPv4())
		} else if ipAddress.IsIPv6() {
			ipBlocklist.TrieV6.Add(ipAddress.ToIPv6())
		}
	}

	return ipBlocklist
}

func setServiceConfig(cloudConfigFromAgent *aikido_types.CloudConfigData, blockListConfig *aikido_types.ListsConfigData) {
	if cloudConfigFromAgent == nil {
		return
	}

	serviceConfigMutex.Lock()
	defer serviceConfigMutex.Unlock()

	serviceConfig.ConfigUpdatedAt = cloudConfigFromAgent.ConfigUpdatedAt

	var endpoints []aikido_types.Endpoint
	for _, ep := range cloudConfigFromAgent.Endpoints {
		endpoints = append(endpoints, aikido_types.Endpoint{
			Method:             ep.Method,
			Route:              ep.Route,
			ForceProtectionOff: ep.ForceProtectionOff,
			AllowedIPAddresses: ep.AllowedIPAddresses,
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

	serviceConfig.BypassedIPs = map[string]bool{}
	for _, ip := range cloudConfigFromAgent.BypassedIPs {
		serviceConfig.BypassedIPs[ip] = true
	}

	if cloudConfigFromAgent.Block == nil {
		globals.AikidoConfig.ConfigMutex.Lock()
		serviceConfig.Block = globals.AikidoConfig.Blocking
		globals.AikidoConfig.ConfigMutex.Unlock()
	} else {
		serviceConfig.Block = *cloudConfigFromAgent.Block
	}

	if blockListConfig != nil {
		serviceConfig.BlockedIPs = map[string]IPBlockList{}
		for _, ipBlocklist := range blockListConfig.BlockedIPAddresses {
			serviceConfig.BlockedIPs[ipBlocklist.Source] = buildIPBlocklist(ipBlocklist.Source, ipBlocklist.Description, ipBlocklist.IPs)
		}

		if blockListConfig.BlockedUserAgents != "" {
			serviceConfig.BlockedUserAgents, _ = regexp.Compile("(?i)" + blockListConfig.BlockedUserAgents)
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

func GetCloudConfigUpdatedAt() int64 {
	serviceConfigMutex.RLock()
	defer serviceConfigMutex.RUnlock()

	return serviceConfig.ConfigUpdatedAt
}

// IsIPBlocked function checks the cloud config mutex for blocked IP addresses.
func IsIPBlocked(ip string) (bool, string) {
	serviceConfigMutex.RLock()
	defer serviceConfigMutex.RUnlock()

	ipAddress, err := ipaddr.NewIPAddressString(ip).ToAddress()
	if err != nil {
		log.Info("Invalid ip address", slog.String("ip", ip))
		return false, ""
	}

	for _, ipBlocklist := range serviceConfig.BlockedIPs {
		if (ipAddress.IsIPv4() && ipBlocklist.TrieV4.ElementContains(ipAddress.ToIPv4())) ||
			(ipAddress.IsIPv6() && ipBlocklist.TrieV6.ElementContains(ipAddress.ToIPv6())) {
			return true, ipBlocklist.Description
		}
	}

	return false, ""
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

func IsIPBypassed(ip string) bool {
	serviceConfigMutex.RLock()
	defer serviceConfigMutex.RUnlock()

	return keyExists(serviceConfig.BypassedIPs, ip)
}

func GetEndpoints() []aikido_types.Endpoint {
	serviceConfigMutex.RLock()
	defer serviceConfigMutex.RUnlock()

	return serviceConfig.Endpoints
}

func keyExists[K comparable, V any](m map[K]V, key K) bool {
	_, exists := m[key]
	return exists
}
