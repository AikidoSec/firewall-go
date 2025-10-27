package agent

import (
	"errors"
	"log/slog"
	"sync/atomic"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/cloud"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/AikidoSec/firewall-go/internal/agent/machine"
	"github.com/AikidoSec/firewall-go/internal/agent/ratelimiting"
	"github.com/AikidoSec/firewall-go/internal/log"
)

var ErrCloudConfigNotUpdated = errors.New("cloud config was not updated")

var cloudClient *cloud.Client

func Init(environmentConfig *aikido_types.EnvironmentConfigData, aikidoConfig *aikido_types.AikidoConfigData) (initOk bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Warn("Recovered from panic", slog.Any("error", r))
			initOk = false
		}
	}()

	machine.Init()
	if !config.Init(environmentConfig, aikidoConfig) {
		return false
	}

	cloudClient = cloud.NewClient(&cloud.ClientConfig{})
	cloudClient.SendStartEvent()

	cloud.StartPolling(cloudClient)

	ratelimiting.Init()

	log.Info("Aikido Agent loaded!", slog.String("version", globals.EnvironmentConfig.Version))
	return true
}

func AgentUninit() error {
	ratelimiting.Uninit()
	cloud.StopPolling()
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
