package helpers

import (
	"github.com/AikidoSec/firewall-go/internal/config"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/zen-internals-agent/aikido_types"
	"github.com/seancfoley/ipaddress-go/ipaddr"
)

func GetCloudConfigUpdatedAt() int64 {
	config.CloudConfigMutex.Lock()
	defer config.CloudConfigMutex.Unlock()

	return config.CloudConfig.ConfigUpdatedAt
}

// IsIPBlocked function checks the cloud config mutex for blocked IP addresses.
func IsIPBlocked(ip string) (bool, string) {
	config.CloudConfigMutex.Lock()
	defer config.CloudConfigMutex.Unlock()

	ipAddress, err := ipaddr.NewIPAddressString(ip).ToAddress()
	if err != nil {
		log.Infof("Invalid ip address: %s\n", ip)
		return false, ""
	}

	for _, ipBlocklist := range config.CloudConfig.BlockedIps {
		if (ipAddress.IsIPv4() && ipBlocklist.TrieV4.ElementContains(ipAddress.ToIPv4())) ||
			(ipAddress.IsIPv6() && ipBlocklist.TrieV6.ElementContains(ipAddress.ToIPv6())) {
			return true, ipBlocklist.Description
		}
	}

	return false, ""
}

// IsUserAgentBlocked returns true if we block (e.g. bot blocking), and a string with the reason why.
func IsUserAgentBlocked(userAgent string) (bool, string) {
	config.CloudConfigMutex.Lock()
	defer config.CloudConfigMutex.Unlock()

	if config.CloudConfig.BlockedUserAgents == nil {
		return false, ""
	}

	if config.CloudConfig.BlockedUserAgents.MatchString(userAgent) {
		return true, "bot detection"
	}

	return false, ""
}

func IsUserBlocked(userID string) bool {
	config.CloudConfigMutex.Lock()
	defer config.CloudConfigMutex.Unlock()
	return KeyExists(config.CloudConfig.BlockedUserIDs, userID)
}

func IsIPBypassed(ip string) bool {
	config.CloudConfigMutex.Lock()
	defer config.CloudConfigMutex.Unlock()

	return KeyExists(config.CloudConfig.BypassedIps, ip)
}

func GetEndpoints() []aikido_types.Endpoint {
	config.CloudConfigMutex.Lock()
	defer config.CloudConfigMutex.Unlock()
	return config.CloudConfig.Endpoints
}

func KeyExists[K comparable, V any](m map[K]V, key K) bool {
	_, exists := m[key]
	return exists
}
