package helpers

import (
	"github.com/AikidoSec/firewall-go/internal/globals"
	"github.com/AikidoSec/firewall-go/internal/log"
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
