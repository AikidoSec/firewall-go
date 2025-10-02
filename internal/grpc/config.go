package grpc

import (
	"regexp"
	"time"

	"github.com/AikidoSec/firewall-go/internal/config"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/zen-internals-agent/aikido_types"
	"github.com/AikidoSec/zen-internals-agent/ipc/protos"
	"github.com/seancfoley/ipaddress-go/ipaddr"
)

var (
	stopChan          chan struct{}
	cloudConfigTicker = time.NewTicker(1 * time.Minute)
)

func buildIpBlocklist(name, description string, ipsList []string) config.IpBlockList {
	ipBlocklist := config.IpBlockList{
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

func setCloudConfig(cloudConfigFromAgent *protos.CloudConfig) {
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

	config.CloudConfig.BlockedUserIds = map[string]bool{}
	for _, userId := range cloudConfigFromAgent.BlockedUserIds {
		config.CloudConfig.BlockedUserIds[userId] = true
	}

	config.CloudConfig.BypassedIps = map[string]bool{}
	for _, ip := range cloudConfigFromAgent.BypassedIps {
		config.CloudConfig.BypassedIps[ip] = true
	}

	if cloudConfigFromAgent.Block {
		config.CloudConfig.Block = 1
	} else {
		config.CloudConfig.Block = 0
	}

	config.CloudConfig.BlockedIps = map[string]config.IpBlockList{}
	for ipBlocklistSource, ipBlocklist := range cloudConfigFromAgent.BlockedIps {
		config.CloudConfig.BlockedIps[ipBlocklistSource] = buildIpBlocklist(ipBlocklistSource, ipBlocklist.Description, ipBlocklist.Ips)
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
