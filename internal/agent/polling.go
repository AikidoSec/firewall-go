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

func refreshCloudConfig() {
	client := GetCloudClient()
	if client == nil {
		return
	}

	// Check if cloud config has been updated
	lastUpdatedAt := client.FetchConfigUpdatedAt()

	// If cloud config was updated before or at the same time, then just return 0 indicating no changes
	if !lastUpdatedAt.After(config.GetCloudConfigUpdatedAt()) {
		return
	}

	// Something has changed, so fetch the full cloud config
	cloudConfig, err := client.FetchConfig()
	if err != nil {
		log.Warn("Error fetching cloud config", slog.Any("error", err))
		return
	}

	updateCloudConfig(client, cloudConfig)
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
			MiddlewareInstalled: stateCollector.IsMiddlewareInstalled(),
		})
	if err != nil {
		log.Warn("Error sending heartbeat event", slog.Any("error", err))
		return
	}

	updateCloudConfig(client, cloudConfig)
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

func resetHeartbeatTicker(newInterval time.Duration) {
	if heartbeatTicker != nil && newInterval > 0 {
		log.Info("Resetting HeartbeatTicker!", slog.String("interval", newInterval.String()))
		heartbeatTicker.Reset(newInterval)
	}
}
