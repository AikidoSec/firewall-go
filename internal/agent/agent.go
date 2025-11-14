package agent

import (
	"errors"
	"log/slog"
	"sync"
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
	cloudClient                 CloudClient
	cloudClientMutex            sync.RWMutex
	heartbeatRoutineChannel     = make(chan struct{})
	heartbeatTicker             *time.Ticker
	configPollingRoutineChannel = make(chan struct{})
	configPollingTicker         *time.Ticker

	// middlewareInstalled boolean value to be reported on heartbeat events
	middlewareInstalled uint32
)

type CloudClient interface {
	SendStartEvent(agentInfo cloud.AgentInfo)
	SendHeartbeatEvent(agentInfo cloud.AgentInfo, data cloud.HeartbeatData) time.Duration
	CheckConfigUpdatedAt() time.Duration
	SendAttackDetectedEvent(agentInfo cloud.AgentInfo, request aikido_types.RequestInfo, attack aikido_types.AttackDetails)
}

func Init(environmentConfig *aikido_types.EnvironmentConfigData, aikidoConfig *aikido_types.AikidoConfigData) error {
	machine.Init()

	if err := config.Init(environmentConfig, aikidoConfig); err != nil {
		return err
	}

	globals.StatsData.StartedAt = utils.GetTime()
	globals.StatsData.MonitoredSinkTimings = make(map[string]aikido_types.MonitoredSinkTimings)

	client := cloud.NewClient(&cloud.ClientConfig{
		Token:            aikidoConfig.Token,
		APIEndpoint:      globals.EnvironmentConfig.Endpoint,
		RealtimeEndpoint: globals.EnvironmentConfig.RealtimeEndpoint,
	})
	SetCloudClient(client)
	go client.SendStartEvent(getAgentInfo())

	startPolling(client)

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

type DetectedAttack struct {
	Request aikido_types.RequestInfo   `json:"request"`
	Attack  aikido_types.AttackDetails `json:"attack"`
}

func OnAttackDetected(attack *DetectedAttack) {
	log.Debug("Reporting attack")

	if client := GetCloudClient(); client != nil {
		client.SendAttackDetectedEvent(getAgentInfo(), attack.Request, attack.Attack)
	}

	storeAttackStats(attack.Attack.Blocked)
}

func OnMonitoredSinkStats(sink string, stats *aikido_types.MonitoredSinkTimings) {
	storeSinkStats(sink, stats)
}

func OnMiddlewareInstalled() {
	log.Debug("Received MiddlewareInstalled")
	atomic.StoreUint32(&middlewareInstalled, 1)
}

func IsMiddlewareInstalled() bool {
	return atomic.LoadUint32(&middlewareInstalled) == 1
}

func handlePollingInterval(fn func() time.Duration) func() {
	return func() {
		newInterval := fn()
		if newInterval > 0 {
			resetHeartbeatTicker(newInterval)
		}
	}
}

func startPolling(client CloudClient) {
	heartbeatTicker = time.NewTicker(10 * time.Minute)
	configPollingTicker = time.NewTicker(1 * time.Minute)

	utils.StartPollingRoutine(heartbeatRoutineChannel, heartbeatTicker,
		handlePollingInterval(func() time.Duration {
			return client.SendHeartbeatEvent(
				getAgentInfo(),
				cloud.HeartbeatData{
					Hostnames:           GetAndClearHostnames(),
					Routes:              GetRoutesAndClear(),
					MiddlewareInstalled: IsMiddlewareInstalled(),
				},
			)
		}))

	utils.StartPollingRoutine(configPollingRoutineChannel, configPollingTicker,
		handlePollingInterval(client.CheckConfigUpdatedAt))
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

func resetHeartbeatTicker(newInterval time.Duration) {
	if heartbeatTicker != nil && newInterval > 0 {
		log.Info("Resetting HeartBeatTicker!", slog.String("interval", newInterval.String()))
		heartbeatTicker.Reset(newInterval)
	}
}

// GetCloudClient returns the current cloud client.
// This should be used instead of direct access to the cloudClient variable.
func GetCloudClient() CloudClient {
	cloudClientMutex.RLock()
	defer cloudClientMutex.RUnlock()
	return cloudClient
}

// SetCloudClient sets the cloud client. Useful for testing with mocks.
func SetCloudClient(client CloudClient) {
	cloudClientMutex.Lock()
	defer cloudClientMutex.Unlock()

	cloudClient = client
}
