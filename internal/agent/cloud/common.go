package cloud

import (
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/AikidoSec/firewall-go/internal/agent/log"
	"github.com/AikidoSec/firewall-go/internal/agent/ratelimiting"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
)

func GetAgentInfo() aikido_types.AgentInfo {
	return aikido_types.AgentInfo{
		DryMode:   !utils.IsBlockingEnabled(),
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

func ResetHeartbeatTicker() {
	if !globals.CloudConfig.ReceivedAnyStats {
		log.Info("Resetting HeartBeatTicker to 1m!")
		HeartBeatTicker.Reset(1 * time.Minute)
	} else {
		if globals.CloudConfig.HeartbeatIntervalInMS >= globals.MinHeartbeatIntervalInMS {
			log.Infof("Resetting HeartBeatTicker to %dms!", globals.CloudConfig.HeartbeatIntervalInMS)
			HeartBeatTicker.Reset(time.Duration(globals.CloudConfig.HeartbeatIntervalInMS) * time.Millisecond)
		}
	}
}

func UpdateRateLimitingConfig() {
	// Convert cloud config endpoints to ratelimiting format
	endpoints := make([]ratelimiting.EndpointConfig, len(globals.CloudConfig.Endpoints))
	for i, endpoint := range globals.CloudConfig.Endpoints {
		endpoints[i] = ratelimiting.EndpointConfig{
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
	ratelimiting.UpdateConfig(endpoints)
}

func ApplyCloudConfig() {
	log.Infof("Applying new cloud config: %v", globals.CloudConfig)
	ResetHeartbeatTicker()
	UpdateRateLimitingConfig()
}

func UpdateListsConfig() bool {
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

	globals.CloudConfig.BlockedIPsList = make(map[string]aikido_types.IPBlocklist)
	for _, blockedIpsGroup := range tempListsConfig.BlockedIPAddresses {
		globals.CloudConfig.BlockedIPsList[blockedIpsGroup.Source] = aikido_types.IPBlocklist{Description: blockedIpsGroup.Description, Ips: blockedIpsGroup.Ips}
	}
	globals.CloudConfig.BlockedUserAgents = tempListsConfig.BlockedUserAgents
	return true
}

func StoreCloudConfig(configReponse []byte) bool {
	globals.CloudConfigMutex.Lock()
	defer globals.CloudConfigMutex.Unlock()

	tempCloudConfig := aikido_types.CloudConfigData{}
	err := json.Unmarshal(configReponse, &tempCloudConfig)
	if err != nil {
		log.Warnf("Failed to unmarshal cloud config!")
		return false
	}
	if tempCloudConfig.ConfigUpdatedAt <= globals.CloudConfig.ConfigUpdatedAt {
		log.Debugf("ConfigUpdatedAt is the same!")
		return true
	}
	globals.CloudConfig = tempCloudConfig
	UpdateListsConfig()
	ApplyCloudConfig()
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
