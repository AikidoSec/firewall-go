package config

import (
	"regexp"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/seancfoley/ipaddress-go/ipaddr"
)

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
		ServiceConfig.Block = config.GetBlocking()
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
