package agent

import (
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/cloud"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/AikidoSec/firewall-go/internal/agent/machine"
	"github.com/AikidoSec/firewall-go/internal/agent/ratelimiting"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
	"github.com/AikidoSec/firewall-go/internal/log"
)

var (
	ErrCloudConfigNotUpdated    = errors.New("cloud config was not updated")
	cloudClient                 *cloud.Client
	heartbeatRoutineChannel     = make(chan struct{})
	heartBeatTicker             *time.Ticker
	configPollingRoutineChannel = make(chan struct{})
	configPollingTicker         *time.Ticker
)

func Init(environmentConfig *aikido_types.EnvironmentConfigData, aikidoConfig *aikido_types.AikidoConfigData) error {
	machine.Init()

	if err := config.Init(environmentConfig, aikidoConfig); err != nil {
		return err
	}

	globals.StatsData.StartedAt = utils.GetTime()
	globals.StatsData.MonitoredSinkTimings = make(map[string]aikido_types.MonitoredSinkTimings)

	cloudClient = cloud.NewClient(&cloud.ClientConfig{
		Token:            aikidoConfig.Token,
		APIEndpoint:      globals.EnvironmentConfig.Endpoint,
		RealtimeEndpoint: globals.EnvironmentConfig.RealtimeEndpoint,
	})
	go cloudClient.SendStartEvent()

	startPolling(cloudClient)

	ratelimiting.Init()

	log.Info("Aikido Agent loaded!", slog.String("version", globals.EnvironmentConfig.Version))
	return nil
}

func AgentUninit() error {
	ratelimiting.Uninit()
	stopPolling()
	config.Uninit()

	log.Info("Aikido Agent unloaded!", slog.String("version", globals.EnvironmentConfig.Version))

	return nil
}

func OnDomain(domain string, port uint32) {
	log.Debug("Received domain", slog.String("domain", domain), slog.Uint64("port", uint64(port)))
	storeDomain(domain, port)
}

func GetRateLimitingStatus(method string, route string, user string, ip string) *ratelimiting.Status {
	log.Debug("Received rate limiting info",
		slog.String("method", method),
		slog.String("route", route),
		slog.String("user", user),
		slog.String("ip", ip))

	return ratelimiting.GetStatus(method, route, user, ip)
}

func OnRequestShutdown(method string, route string, statusCode int, user string, ip string, apiSpec *aikido_types.APISpec) {
	log.Debug("Received request metadata",
		slog.String("method", method),
		slog.String("route", route),
		slog.Int("statusCode", statusCode),
		slog.String("user", user),
		slog.String("ip", ip))

	go storeStats()
	go storeRoute(method, route, apiSpec)
	go ratelimiting.UpdateCounts(method, route, user, ip)
}

func OnUser(id string, username string, ip string) {
	log.Debug("Received user event", slog.String("id", id))
	onUserEvent(id, username, ip)
}

func OnAttackDetected(attack *aikido_types.DetectedAttack) {
	log.Debug("Reporting attack")

	if cloudClient != nil {
		cloudClient.SendAttackDetectedEvent(attack)
	}

	storeAttackStats(attack.Attack.Blocked)
}

func OnMonitoredSinkStats(sink string, stats *aikido_types.MonitoredSinkTimings) {
	storeSinkStats(sink, stats)
}

func OnMiddlewareInstalled() {
	log.Debug("Received MiddlewareInstalled")
	atomic.StoreUint32(&globals.MiddlewareInstalled, 1)
}

func startPolling(client *cloud.Client) {
	// Initialize tickers with default intervals
	heartBeatTicker = time.NewTicker(10 * time.Minute)
	configPollingTicker = time.NewTicker(1 * time.Minute)

	utils.StartPollingRoutine(heartbeatRoutineChannel, heartBeatTicker, func() {
		newInterval := client.SendHeartbeatEvent()
		if newInterval > 0 {
			resetHeartbeatTicker(newInterval)
		}
	})

	utils.StartPollingRoutine(configPollingRoutineChannel, configPollingTicker, func() {
		newInterval := client.CheckConfigUpdatedAt()
		if newInterval > 0 {
			resetHeartbeatTicker(newInterval)
		}
	})
}

func stopPolling() {
	utils.StopPollingRoutine(heartbeatRoutineChannel)
	utils.StopPollingRoutine(configPollingRoutineChannel)
	if heartBeatTicker != nil {
		heartBeatTicker.Stop()
	}
	if configPollingTicker != nil {
		configPollingTicker.Stop()
	}
}

func resetHeartbeatTicker(newInterval time.Duration) {
	if heartBeatTicker != nil && newInterval > 0 {
		log.Info("Resetting HeartBeatTicker!", slog.String("interval", newInterval.String()))
		heartBeatTicker.Reset(newInterval)
	}
}
