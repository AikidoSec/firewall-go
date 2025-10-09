package grpc

import (
	"regexp"
	"time"

	"github.com/AikidoSec/firewall-go/agent/aikido_types"
	agentConfig "github.com/AikidoSec/firewall-go/agent/config"
	"github.com/AikidoSec/firewall-go/internal/config"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/seancfoley/ipaddress-go/ipaddr"
)

var (
	stopChan          chan struct{}
	cloudConfigTicker = time.NewTicker(1 * time.Minute)
)

func buildIPBlocklist(name, description string, ipsList []string) config.IPBlockList {
	ipBlocklist := config.IPBlockList{
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

func setCloudConfig(cloudConfigFromAgent *aikido_types.CloudConfigData) {
	if cloudConfigFromAgent == nil {
		return
	}

	config.CloudConfigMutex.Lock()
	defer config.CloudConfigMutex.Unlock()

	config.CloudConfig.ConfigUpdatedAt = cloudConfigFromAgent.ConfigUpdatedAt

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
	config.CloudConfig.Endpoints = endpoints

	config.CloudConfig.BlockedUserIDs = map[string]bool{}
	for _, userID := range cloudConfigFromAgent.BlockedUserIds {
		config.CloudConfig.BlockedUserIDs[userID] = true
	}

	config.CloudConfig.BypassedIPs = map[string]bool{}
	for _, ip := range cloudConfigFromAgent.BypassedIPs {
		config.CloudConfig.BypassedIPs[ip] = true
	}

	if cloudConfigFromAgent.Block == nil {
		config.CloudConfig.Block = agentConfig.GetBlocking()
	} else {
		config.CloudConfig.Block = *cloudConfigFromAgent.Block
	}

	config.CloudConfig.BlockedIPs = map[string]config.IPBlockList{}
	for ipBlocklistSource, ipBlocklist := range cloudConfigFromAgent.BlockedIPsList {
		config.CloudConfig.BlockedIPs[ipBlocklistSource] = buildIPBlocklist(ipBlocklistSource, ipBlocklist.Description, ipBlocklist.Ips)
	}

	if cloudConfigFromAgent.BlockedUserAgents != "" {
		config.CloudConfig.BlockedUserAgents, _ = regexp.Compile("(?i)" + cloudConfigFromAgent.BlockedUserAgents)
	} else {
		config.CloudConfig.BlockedUserAgents = nil
	}
}

func startCloudConfigRoutine() {
	GetCloudConfig()

	stopChan = make(chan struct{})

	go func() {
		for {
			select {
			case <-cloudConfigTicker.C:
				GetCloudConfig()
			case <-stopChan:
				cloudConfigTicker.Stop()
				return
			}
		}
	}()
}

func stopCloudConfigRoutine() {
	if stopChan != nil {
		close(stopChan)
	}
}
