package config

import (
	"regexp"
	"sync"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/seancfoley/ipaddress-go/ipaddr"
)

var ServiceConfig ServiceConfigData
var ServiceConfigMutex sync.RWMutex

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
			log.Infof("Invalid address for %s: %s\n", name, ip)
			continue
		}

		if ipAddress.IsIPv4() {
			ipBlocklist.TrieV4.Add(ipAddress.ToIPv4())
		} else if ipAddress.IsIPv6() {
			ipBlocklist.TrieV6.Add(ipAddress.ToIPv6())
		}
	}

	log.Debugf("%s (v4): %v", name, ipBlocklist.TrieV4)
	log.Debugf("%s (v6): %v", name, ipBlocklist.TrieV6)
	return ipBlocklist
}

func setServiceConfig(cloudConfigFromAgent *aikido_types.CloudConfigData) {
	if cloudConfigFromAgent == nil {
		return
	}

	ServiceConfigMutex.Lock()
	defer ServiceConfigMutex.Unlock()

	ServiceConfig.ConfigUpdatedAt = cloudConfigFromAgent.ConfigUpdatedAt

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
	ServiceConfig.Endpoints = endpoints

	ServiceConfig.BlockedUserIDs = map[string]bool{}
	for _, userID := range cloudConfigFromAgent.BlockedUserIds {
		ServiceConfig.BlockedUserIDs[userID] = true
	}

	ServiceConfig.BypassedIPs = map[string]bool{}
	for _, ip := range cloudConfigFromAgent.BypassedIPs {
		ServiceConfig.BypassedIPs[ip] = true
	}

	if cloudConfigFromAgent.Block == nil {
		ServiceConfig.Block = GetBlocking()
	} else {
		ServiceConfig.Block = *cloudConfigFromAgent.Block
	}

	ServiceConfig.BlockedIPs = map[string]IPBlockList{}
	for ipBlocklistSource, ipBlocklist := range cloudConfigFromAgent.BlockedIPsList {
		ServiceConfig.BlockedIPs[ipBlocklistSource] = buildIPBlocklist(ipBlocklistSource, ipBlocklist.Description, ipBlocklist.Ips)
	}

	if cloudConfigFromAgent.BlockedUserAgents != "" {
		ServiceConfig.BlockedUserAgents, _ = regexp.Compile("(?i)" + cloudConfigFromAgent.BlockedUserAgents)
	} else {
		ServiceConfig.BlockedUserAgents = nil
	}
}

func UpdateServiceConfig(cloudConfig *aikido_types.CloudConfigData) {
	log.Debugf("Got cloud config: %v", cloudConfig)
	setServiceConfig(cloudConfig)
}

var CollectAPISchema bool

func GetCloudConfigUpdatedAt() int64 {
	ServiceConfigMutex.RLock()
	defer ServiceConfigMutex.RUnlock()

	return ServiceConfig.ConfigUpdatedAt
}

// IsIPBlocked function checks the cloud config mutex for blocked IP addresses.
func IsIPBlocked(ip string) (bool, string) {
	ServiceConfigMutex.RLock()
	defer ServiceConfigMutex.RUnlock()

	ipAddress, err := ipaddr.NewIPAddressString(ip).ToAddress()
	if err != nil {
		log.Infof("Invalid ip address: %s\n", ip)
		return false, ""
	}

	for _, ipBlocklist := range ServiceConfig.BlockedIPs {
		if (ipAddress.IsIPv4() && ipBlocklist.TrieV4.ElementContains(ipAddress.ToIPv4())) ||
			(ipAddress.IsIPv6() && ipBlocklist.TrieV6.ElementContains(ipAddress.ToIPv6())) {
			return true, ipBlocklist.Description
		}
	}

	return false, ""
}

// IsUserAgentBlocked returns true if we block (e.g. bot blocking), and a string with the reason why.
func IsUserAgentBlocked(userAgent string) (bool, string) {
	ServiceConfigMutex.RLock()
	defer ServiceConfigMutex.RUnlock()

	if ServiceConfig.BlockedUserAgents == nil {
		return false, ""
	}

	if ServiceConfig.BlockedUserAgents.MatchString(userAgent) {
		return true, "bot detection"
	}

	return false, ""
}

func IsUserBlocked(userID string) bool {
	ServiceConfigMutex.RLock()
	defer ServiceConfigMutex.RUnlock()

	return keyExists(ServiceConfig.BlockedUserIDs, userID)
}

func IsIPBypassed(ip string) bool {
	ServiceConfigMutex.RLock()
	defer ServiceConfigMutex.RUnlock()

	return keyExists(ServiceConfig.BypassedIPs, ip)
}

func GetEndpoints() []aikido_types.Endpoint {
	ServiceConfigMutex.RLock()
	defer ServiceConfigMutex.RUnlock()

	return ServiceConfig.Endpoints
}

func keyExists[K comparable, V any](m map[K]V, key K) bool {
	_, exists := m[key]
	return exists
}
