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

// CheckConfigUpdatedAt checks if the config has been updated and returns the new heartbeat interval if updated.
func (c *Client) CheckConfigUpdatedAt() time.Duration {
	response, err := c.sendCloudRequest(c.realtimeEndpoint, configUpdatedAtAPIRoute, configUpdatedAtMethod, nil)
	if err != nil {
		logCloudRequestError("Error in sending polling config request: ", err)
		return 0
	}

	cloudConfigUpdatedAt := aikido_types.CloudConfigUpdatedAt{}
	err = json.Unmarshal(response, &cloudConfigUpdatedAt)
	if err != nil {
		return 0
	}

	if cloudConfigUpdatedAt.ConfigUpdatedAt <= config.GetCloudConfigUpdatedAt() {
		return 0
	}

	configResponse, err := c.sendCloudRequest(c.apiEndpoint, configAPIRoute, configAPIMethod, nil)
	if err != nil {
		logCloudRequestError("Error in sending config request: ", err)
		return 0
	}

	return c.storeCloudConfig(configResponse)
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

// storeCloudConfig applies cloud configuration if newer than the current
// version. Returns the calculated heartbeat interval (0 if unchanged or error).
func (c *Client) storeCloudConfig(configResponse []byte) time.Duration {
	cloudConfig := &aikido_types.CloudConfigData{}
	err := json.Unmarshal(configResponse, &cloudConfig)
	if err != nil {
		log.Warn("Failed to unmarshal cloud config!", slog.Any("error", err))
		return 0
	}
	if cloudConfig.ConfigUpdatedAt <= config.GetCloudConfigUpdatedAt() {
		return 0
	}

	c.updateListsConfig(cloudConfig)
	updateRateLimitingConfig(cloudConfig.Endpoints)

	config.UpdateServiceConfig(cloudConfig)
	return calculateHeartbeatInterval(cloudConfig.HeartbeatIntervalInMS, cloudConfig.ReceivedAnyStats)
}

// calculateHeartbeatInterval calculates the heartbeat interval based on config.
// Returns 1 minute if no stats received, or the provided interval if it meets the minimum threshold.
func calculateHeartbeatInterval(heartbeatIntervalInMS int, receivedAnyStats bool) time.Duration {
	if !receivedAnyStats {
		return 1 * time.Minute
	} else if heartbeatIntervalInMS >= minHeartbeatIntervalInMS {
		log.Info("Calculating heartbeat interval!", slog.Int("interval", heartbeatIntervalInMS))
		return time.Duration(heartbeatIntervalInMS) * time.Millisecond
	}
	return 0
}

// updateRateLimitingConfig applies endpoint rate limiting configuration
// from the cloud config.
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
