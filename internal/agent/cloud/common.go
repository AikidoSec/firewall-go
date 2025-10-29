package cloud

import (
	"encoding/json"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/AikidoSec/firewall-go/internal/agent/machine"
	"github.com/AikidoSec/firewall-go/internal/agent/ratelimiting"
	"github.com/AikidoSec/firewall-go/internal/log"
)

var loggedTokenError atomic.Bool

func getAgentInfo() aikido_types.AgentInfo {
	return aikido_types.AgentInfo{
		DryMode:   !config.IsBlockingEnabled(),
		Hostname:  machine.Machine.HostName,
		Version:   globals.EnvironmentConfig.Version,
		IPAddress: machine.Machine.IPAddress,
		OS: aikido_types.OsInfo{
			Name:    machine.Machine.OS,
			Version: machine.Machine.OSVersion,
		},
		Platform: aikido_types.PlatformInfo{
			Name:    globals.EnvironmentConfig.PlatformName,
			Version: globals.EnvironmentConfig.PlatformVersion,
		},
		Packages: make(map[string]string, 0),
		NodeEnv:  "",
		Library:  globals.EnvironmentConfig.Library,
	}
}

func resetHeartbeatTicker(heartbeatIntervalInMS int, receivedAnyStats bool) {
	if !receivedAnyStats {
		log.Info("Resetting HeartBeatTicker to 1m!")
		heartBeatTicker.Reset(1 * time.Minute)
	} else if heartbeatIntervalInMS >= globals.MinHeartbeatIntervalInMS {
		log.Info("Resetting HeartBeatTicker!", slog.Int("interval", heartbeatIntervalInMS))
		heartBeatTicker.Reset(time.Duration(heartbeatIntervalInMS) * time.Millisecond)
	}
}

func updateRateLimitingConfig(endpoints []aikido_types.Endpoint) {
	// Convert cloud config endpoints to ratelimiting format
	endpointConfigs := make([]ratelimiting.EndpointConfig, len(endpoints))
	for i, endpoint := range endpoints {
		endpointConfigs[i] = ratelimiting.EndpointConfig{
			Method: endpoint.Method,
			Route:  endpoint.Route,
			RateLimiting: struct {
				Enabled        bool
				MaxRequests    int
				WindowSizeInMS int
			}{
				Enabled:        endpoint.RateLimiting.Enabled,
				MaxRequests:    endpoint.RateLimiting.MaxRequests,
				WindowSizeInMS: endpoint.RateLimiting.WindowSizeInMS,
			},
		}
	}
	ratelimiting.UpdateConfig(endpointConfigs)
}

func (c *Client) updateListsConfig(cloudConfig *aikido_types.CloudConfigData) bool {
	response, err := c.sendCloudRequest(globals.EnvironmentConfig.Endpoint, globals.ListsAPI, globals.ListsAPIMethod, nil)
	if err != nil {
		logCloudRequestError("Error in sending lists request: ", err)
		return false
	}

	tempListsConfig := aikido_types.ListsConfigData{}
	err = json.Unmarshal(response, &tempListsConfig)
	if err != nil {
		log.Warn("Failed to unmarshal lists config!")
		return false
	}

	cloudConfig.BlockedIPsList = make(map[string]aikido_types.IPBlocklist)
	for _, blockedIpsGroup := range tempListsConfig.BlockedIPAddresses {
		cloudConfig.BlockedIPsList[blockedIpsGroup.Source] = aikido_types.IPBlocklist{Description: blockedIpsGroup.Description, Ips: blockedIpsGroup.Ips}
	}
	cloudConfig.BlockedUserAgents = tempListsConfig.BlockedUserAgents
	return true
}

func (c *Client) storeCloudConfig(configReponse []byte) bool {
	cloudConfig := &aikido_types.CloudConfigData{}
	err := json.Unmarshal(configReponse, &cloudConfig)
	if err != nil {
		log.Warn("Failed to unmarshal cloud config!")
		return false
	}
	if cloudConfig.ConfigUpdatedAt <= config.GetCloudConfigUpdatedAt() {
		log.Debug("ConfigUpdatedAt is the same!")
		return true
	}

	c.updateListsConfig(cloudConfig)
	resetHeartbeatTicker(cloudConfig.HeartbeatIntervalInMS, cloudConfig.ReceivedAnyStats)
	updateRateLimitingConfig(cloudConfig.Endpoints)

	config.UpdateServiceConfig(cloudConfig)
	return true
}

func logCloudRequestError(text string, err error) {
	if errors.Is(err, ErrNoTokenSet) {
		if !loggedTokenError.CompareAndSwap(false, true) {
			return
		}
	}
	log.Warn(text, slog.Any("error", err))
}
