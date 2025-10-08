package config

import (
	"regexp"

	"github.com/AikidoSec/firewall-go/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/seancfoley/ipaddress-go/ipaddr"
)

var CollectAPISchema bool

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

type CloudConfigData struct {
	ConfigUpdatedAt   int64
	Endpoints         []aikido_types.Endpoint
	BlockedUserIDs    map[string]bool
	BypassedIPs       map[string]bool
	BlockedIPs        map[string]IPBlockList
	BlockedUserAgents *regexp.Regexp
	Block             bool
}

func GetCloudConfigUpdatedAt() int64 {
	CloudConfigMutex.RLock()
	defer CloudConfigMutex.RUnlock()

	return CloudConfig.ConfigUpdatedAt
}

// IsIPBlocked function checks the cloud config mutex for blocked IP addresses.
func IsIPBlocked(ip string) (bool, string) {
	CloudConfigMutex.RLock()
	defer CloudConfigMutex.RUnlock()

	ipAddress, err := ipaddr.NewIPAddressString(ip).ToAddress()
	if err != nil {
		log.Infof("Invalid ip address: %s\n", ip)
		return false, ""
	}

	for _, ipBlocklist := range CloudConfig.BlockedIPs {
		if (ipAddress.IsIPv4() && ipBlocklist.TrieV4.ElementContains(ipAddress.ToIPv4())) ||
			(ipAddress.IsIPv6() && ipBlocklist.TrieV6.ElementContains(ipAddress.ToIPv6())) {
			return true, ipBlocklist.Description
		}
	}

	return false, ""
}

// IsUserAgentBlocked returns true if we block (e.g. bot blocking), and a string with the reason why.
func IsUserAgentBlocked(userAgent string) (bool, string) {
	CloudConfigMutex.RLock()
	defer CloudConfigMutex.RUnlock()

	if CloudConfig.BlockedUserAgents == nil {
		return false, ""
	}

	if CloudConfig.BlockedUserAgents.MatchString(userAgent) {
		return true, "bot detection"
	}

	return false, ""
}

func IsUserBlocked(userID string) bool {
	CloudConfigMutex.RLock()
	defer CloudConfigMutex.RUnlock()

	return keyExists(CloudConfig.BlockedUserIDs, userID)
}

func IsIPBypassed(ip string) bool {
	CloudConfigMutex.RLock()
	defer CloudConfigMutex.RUnlock()

	return keyExists(CloudConfig.BypassedIPs, ip)
}

func GetEndpoints() []aikido_types.Endpoint {
	CloudConfigMutex.RLock()
	defer CloudConfigMutex.RUnlock()

	return CloudConfig.Endpoints
}

func keyExists[K comparable, V any](m map[K]V, key K) bool {
	_, exists := m[key]
	return exists
}
