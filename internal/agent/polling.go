package agent

import (
	"log/slog"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/cloud"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
	"github.com/AikidoSec/firewall-go/internal/log"
)

var (
	heartbeatRoutine     *utils.PollingRoutine
	configPollingRoutine *utils.PollingRoutine

	minHeartbeatIntervalInMS = 120000
)

func startPolling() {
	heartbeatRoutine = utils.StartPollingRoutine(10*time.Minute, sendHeartbeatEvent)
	configPollingRoutine = utils.StartPollingRoutine(1*time.Minute, refreshCloudConfig)
}

func stopPolling() {
	if heartbeatRoutine != nil {
		heartbeatRoutine.Stop()
	}
	if configPollingRoutine != nil {
		configPollingRoutine.Stop()
	}
}

// refreshCloudConfig checks if config has changed before fetching the full config
// to avoid unnecessary calls to the API
func refreshCloudConfig() {
	client := GetCloudClient()
	if client == nil {
		return
	}

	// Check if cloud config has been updated
	lastUpdatedAt := client.FetchConfigUpdatedAt()
	if !lastUpdatedAt.After(config.GetCloudConfigUpdatedAt()) {
		return
	}

	// Something has changed, so fetch the full cloud config
	cloudConfig, err := client.FetchConfig()
	if err != nil {
		log.Warn("Error fetching cloud config", slog.Any("error", err))
		return
	}

	applyCloudConfig(client, cloudConfig)
}

func sendHeartbeatEvent() {
	client := GetCloudClient()
	if client == nil {
		return
	}

	cloudConfig, err := client.SendHeartbeatEvent(getAgentInfo(),
		cloud.HeartbeatData{
			Hostnames:           stateCollector.GetAndClearHostnames(),
			Routes:              stateCollector.GetRoutesAndClear(),
			Users:               GetUsersAndClear(),
			Stats:               stateCollector.Stats().GetAndClear(),
			MiddlewareInstalled: stateCollector.IsMiddlewareInstalled(),
		})
	if err != nil {
		log.Warn("Error sending heartbeat event", slog.Any("error", err))
		return
	}

	applyCloudConfig(client, cloudConfig)
}

// calculateHeartbeatInterval returns a faster polling interval (1 minute) for new agents
// until they send their first stats, then switches to the cloud-configured interval
// (minimum 2 minutes) to reduce unnecessary load.
func calculateHeartbeatInterval(heartbeatIntervalInMS int, receivedAnyStats bool) time.Duration {
	if !receivedAnyStats {
		return 1 * time.Minute
	} else if heartbeatIntervalInMS >= minHeartbeatIntervalInMS {
		log.Debug("Calculating heartbeat interval", slog.Int("interval", heartbeatIntervalInMS))
		return time.Duration(heartbeatIntervalInMS) * time.Millisecond
	}
	return 0
}

func resetHeartbeatTicker(newInterval time.Duration) {
	if heartbeatRoutine != nil && newInterval > 0 {
		log.Debug("Resetting HeartbeatTicker", slog.String("interval", newInterval.String()))
		heartbeatRoutine.Reset(newInterval)
	}
}
