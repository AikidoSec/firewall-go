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
	heartbeatRoutineChannel     = make(chan struct{})
	heartbeatTicker             *time.Ticker
	configPollingRoutineChannel = make(chan struct{})
	configPollingTicker         *time.Ticker

	minHeartbeatIntervalInMS = 120000
)

func startPolling() {
	heartbeatTicker = time.NewTicker(10 * time.Minute)
	configPollingTicker = time.NewTicker(1 * time.Minute)

	utils.StartPollingRoutine(heartbeatRoutineChannel, heartbeatTicker, sendHeartbeatEvent)
	utils.StartPollingRoutine(configPollingRoutineChannel, configPollingTicker, refreshCloudConfig)
}

func stopPolling() {
	utils.StopPollingRoutine(heartbeatRoutineChannel)
	utils.StopPollingRoutine(configPollingRoutineChannel)

	if heartbeatTicker != nil {
		heartbeatTicker.Stop()
	}
	if configPollingTicker != nil {
		configPollingTicker.Stop()
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
	if heartbeatTicker != nil && newInterval > 0 {
		log.Debug("Resetting HeartbeatTicker", slog.String("interval", newInterval.String()))
		heartbeatTicker.Reset(newInterval)
	}
}
