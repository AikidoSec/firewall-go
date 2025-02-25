package helpers

import (
	"github.com/AikidoSec/firewall-go/internal/globals"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/zen-internals-agent/aikido_types"
	"github.com/seancfoley/ipaddress-go/ipaddr"
)

func GetCloudConfigUpdatedAt() int64 {
	globals.CloudConfigMutex.Lock()
	defer globals.CloudConfigMutex.Unlock()

	return globals.CloudConfig.ConfigUpdatedAt
}

// IsIpBlocked function checks the cloud config mutex for blocked IP addresses.
func IsIpBlocked(ip string) (bool, string) {
	globals.CloudConfigMutex.Lock()
	defer globals.CloudConfigMutex.Unlock()

	ipAddress, err := ipaddr.NewIPAddressString(ip).ToAddress()
	if err != nil {
		log.Infof("Invalid ip address: %s\n", ip)
		return false, ""
	}

	for _, ipBlocklist := range globals.CloudConfig.BlockedIps {
		if (ipAddress.IsIPv4() && ipBlocklist.TrieV4.ElementContains(ipAddress.ToIPv4())) ||
			(ipAddress.IsIPv6() && ipBlocklist.TrieV6.ElementContains(ipAddress.ToIPv6())) {
			return true, ipBlocklist.Description
		}
	}

	return false, ""
}

// IsUserAgentBlocked returns true if we block (e.g. bot blocking), and a string with the reason why.
func IsUserAgentBlocked(userAgent string) (bool, string) {
	globals.CloudConfigMutex.Lock()
	defer globals.CloudConfigMutex.Unlock()

	if globals.CloudConfig.BlockedUserAgents == nil {
		return false, ""
	}

	if globals.CloudConfig.BlockedUserAgents.MatchString(userAgent) {
		return true, "bot detection"
	}

	return false, ""
}

func IsUserBlocked(userID string) bool {
	globals.CloudConfigMutex.Lock()
	defer globals.CloudConfigMutex.Unlock()
	return KeyExists(globals.CloudConfig.BlockedUserIds, userID)
}

func IsIpBypassed(ip string) bool {
	globals.CloudConfigMutex.Lock()
	defer globals.CloudConfigMutex.Unlock()
	
	if KeyExists(globals.CloudConfig.BypassedIps, ip) {
		return true
	}

	return false
}

func GetEndpoints() []aikido_types.Endpoint {
	globals.CloudConfigMutex.Lock()
	defer globals.CloudConfigMutex.Unlock()
	return globals.CloudConfig.Endpoints
}
func KeyExists[K comparable, V any](m map[K]V, key K) bool {
	_, exists := m[key]
	return exists
}
