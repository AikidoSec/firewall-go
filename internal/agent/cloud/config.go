package cloud

import (
	"encoding/json"
	"log/slog"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/ratelimiting"
	"github.com/AikidoSec/firewall-go/internal/log"
)

const (
	configUpdatedAtMethod   = "GET"
	configUpdatedAtAPIRoute = "/config"
	configAPIMethod         = "GET"
	configAPIRoute          = "/api/runtime/config"
	listsAPIMethod          = "GET"
	listsAPIRoute           = "api/runtime/firewall/lists"

	minHeartbeatIntervalInMS = 120000
)

func (c *Client) CheckConfigUpdatedAt() {
	response, err := c.sendCloudRequest(c.realtimeEndpoint, configUpdatedAtAPIRoute, configUpdatedAtMethod, nil)
	if err != nil {
		logCloudRequestError("Error in sending polling config request: ", err)
		return
	}

	cloudConfigUpdatedAt := aikido_types.CloudConfigUpdatedAt{}
	err = json.Unmarshal(response, &cloudConfigUpdatedAt)
	if err != nil {
		return
	}

	if cloudConfigUpdatedAt.ConfigUpdatedAt <= config.GetCloudConfigUpdatedAt() {
		return
	}

	configResponse, err := c.sendCloudRequest(c.apiEndpoint, configAPIRoute, configAPIMethod, nil)
	if err != nil {
		logCloudRequestError("Error in sending config request: ", err)
		return
	}

	c.storeCloudConfig(configResponse)
}

// updateListsConfig fetches firewall blocklists to keep local security rules synchronized with cloud configuration.
func (c *Client) updateListsConfig(cloudConfig *aikido_types.CloudConfigData) bool {
	response, err := c.sendCloudRequest(c.apiEndpoint, listsAPIRoute, listsAPIMethod, nil)
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

func (c *Client) storeCloudConfig(configResponse []byte) bool {
	cloudConfig := &aikido_types.CloudConfigData{}
	err := json.Unmarshal(configResponse, &cloudConfig)
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

func resetHeartbeatTicker(heartbeatIntervalInMS int, receivedAnyStats bool) {
	if !receivedAnyStats {
		log.Info("Resetting HeartBeatTicker to 1m!")
		heartBeatTicker.Reset(1 * time.Minute)
	} else if heartbeatIntervalInMS >= minHeartbeatIntervalInMS {
		log.Info("Resetting HeartBeatTicker!", slog.Int("interval", heartbeatIntervalInMS))
		heartBeatTicker.Reset(time.Duration(heartbeatIntervalInMS) * time.Millisecond)
	}
}

func updateRateLimitingConfig(endpoints []aikido_types.Endpoint) {
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
