package agent

import (
	"log/slog"
	"sync"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/ratelimiting"
	"github.com/AikidoSec/firewall-go/internal/log"
)

var cloudConfigMutex sync.Mutex

// applyCloudConfig applies a new cloud config if it's newer than the current one.
// This includes updating service config, rate limiting rules, and heartbeat interval.
func applyCloudConfig(client CloudClient, cloudConfig *aikido_types.CloudConfigData) {
	cloudConfigMutex.Lock()
	defer cloudConfigMutex.Unlock()

	if !cloudConfig.UpdatedAt().After(config.GetCloudConfigUpdatedAt()) {
		return
	}

	// Fetch lists
	listsConfig, err := client.FetchListsConfig()
	if err != nil {
		log.Warn("Error fetching lists config", slog.Any("error", err))
		return
	}

	updateRateLimitingConfig(cloudConfig.Endpoints)
	config.UpdateServiceConfig(cloudConfig, listsConfig)

	newInterval := calculateHeartbeatInterval(cloudConfig.HeartbeatIntervalInMS, cloudConfig.ReceivedAnyStats)
	if newInterval > 0 {
		resetHeartbeatTicker(newInterval)
	}
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
