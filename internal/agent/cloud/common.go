package cloud

import (
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/AikidoSec/firewall-go/internal/agent/log"
	"github.com/AikidoSec/firewall-go/internal/agent/ratelimiting"
)

func GetAgentInfo() aikido_types.AgentInfo {
	return aikido_types.AgentInfo{
		DryMode:   !config.IsBlockingEnabled(),
		Hostname:  globals.Machine.HostName,
		Version:   globals.EnvironmentConfig.Version,
		IPAddress: globals.Machine.IPAddress,
		OS: aikido_types.OsInfo{
			Name:    globals.Machine.OS,
			Version: globals.Machine.OSVersion,
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
		HeartBeatTicker.Reset(1 * time.Minute)
	} else {
		if heartbeatIntervalInMS >= globals.MinHeartbeatIntervalInMS {
			log.Infof("Resetting HeartBeatTicker to %dms!", heartbeatIntervalInMS)
			HeartBeatTicker.Reset(time.Duration(heartbeatIntervalInMS) * time.Millisecond)
		}
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

func applyCloudConfig(cloudConfig *aikido_types.CloudConfigData) {
	log.Infof("Applying new cloud config: %v", cloudConfig)
	resetHeartbeatTicker(cloudConfig.HeartbeatIntervalInMS, cloudConfig.ReceivedAnyStats)
	updateRateLimitingConfig(cloudConfig.Endpoints)
}

func updateListsConfig(cloudConfig *aikido_types.CloudConfigData) bool {
	response, err := SendCloudRequest(globals.EnvironmentConfig.Endpoint, globals.ListsAPI, globals.ListsAPIMethod, nil)
	if err != nil {
		LogCloudRequestError("Error in sending lists request: ", err)
		return false
	}

	tempListsConfig := aikido_types.ListsConfigData{}
	err = json.Unmarshal(response, &tempListsConfig)
	if err != nil {
		log.Warnf("Failed to unmarshal lists config!")
		return false
	}

	cloudConfig.BlockedIPsList = make(map[string]aikido_types.IPBlocklist)
	for _, blockedIpsGroup := range tempListsConfig.BlockedIPAddresses {
		cloudConfig.BlockedIPsList[blockedIpsGroup.Source] = aikido_types.IPBlocklist{Description: blockedIpsGroup.Description, Ips: blockedIpsGroup.Ips}
	}
	cloudConfig.BlockedUserAgents = tempListsConfig.BlockedUserAgents
	return true
}

func storeCloudConfig(configReponse []byte) bool {
	tempCloudConfig := &aikido_types.CloudConfigData{}
	err := json.Unmarshal(configReponse, &tempCloudConfig)
	if err != nil {
		log.Warnf("Failed to unmarshal cloud config!")
		return false
	}
	if tempCloudConfig.ConfigUpdatedAt <= config.GetCloudConfigUpdatedAt() {
		log.Debugf("ConfigUpdatedAt is the same!")
		return true
	}

	updateListsConfig(tempCloudConfig)
	applyCloudConfig(tempCloudConfig)

	config.UpdateServiceConfig(tempCloudConfig)
	return true
}

func LogCloudRequestError(text string, err error) {
	if atomic.LoadUint32(&globals.GotTraffic) == 0 {
		// Wait for at least one request before we start logging any cloud request errors, including "no token set"
		// We need to do that because the token can be passed later via gRPC and the first request.
		return
	}
	if err.Error() == "no token set" {
		if atomic.LoadUint32(&globals.LoggedTokenError) != 0 {
			// Only report the "no token set" once, so we don't pollute the logs
			return
		}
		atomic.StoreUint32(&globals.LoggedTokenError, 1)
	}
	log.Warn(text, err)
}
