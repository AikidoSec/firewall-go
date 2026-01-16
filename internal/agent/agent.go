package agent

import (
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/cloud"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/AikidoSec/firewall-go/internal/agent/machine"
	"github.com/AikidoSec/firewall-go/internal/agent/ratelimiting"
	"github.com/AikidoSec/firewall-go/internal/agent/state"
	"github.com/AikidoSec/firewall-go/internal/agent/state/stats"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/attackwave"
)

var (
	cloudClient      CloudClient
	cloudClientMutex sync.RWMutex

	stateCollector     = state.NewCollector()
	attackWaveDetector = attackwave.NewDetector(nil)
)

type CloudClient interface {
	SendStartEvent(agentInfo cloud.AgentInfo) (*aikido_types.CloudConfigData, error)
	SendHeartbeatEvent(agentInfo cloud.AgentInfo, data cloud.HeartbeatData) (*aikido_types.CloudConfigData, error)
	FetchConfigUpdatedAt() time.Time
	FetchConfig() (*aikido_types.CloudConfigData, error)
	FetchListsConfig() (*aikido_types.ListsConfigData, error)
	SendAttackDetectedEvent(agentInfo cloud.AgentInfo, request aikido_types.RequestInfo, attack aikido_types.AttackDetails)
	SendAttackWaveDetectedEvent(agentInfo cloud.AgentInfo, request cloud.AttackWaveRequestInfo, attack cloud.AttackWaveDetails)
}

func Init(environmentConfig *aikido_types.EnvironmentConfigData, aikidoConfig *aikido_types.AikidoConfigData) error {
	machine.Init()

	if err := config.Init(environmentConfig, aikidoConfig); err != nil {
		return err
	}

	if environmentConfig.ZenDisabled {
		return nil
	}

	Stats().SetStartedAt(utils.GetTime())

	client := cloud.NewClient(&cloud.ClientConfig{
		Token:            aikidoConfig.Token,
		APIEndpoint:      globals.EnvironmentConfig.Endpoint,
		RealtimeEndpoint: globals.EnvironmentConfig.RealtimeEndpoint,
	})
	SetCloudClient(client)

	go func() {
		cloudConfig, err := client.SendStartEvent(getAgentInfo())
		if err != nil {
			log.Warn("Error sending start event", slog.Any("error", err))
			return
		}

		applyCloudConfig(client, cloudConfig)
	}()

	startPolling()

	ratelimiting.Init()

	return nil
}

func AgentUninit() error {
	ratelimiting.Uninit()
	stopPolling()
	config.Uninit()

	return nil
}

func OnDomain(domain string, port uint32) {
	log.Debug("Received domain", slog.String("domain", domain), slog.Uint64("port", uint64(port)))
	stateCollector.StoreHostname(domain, port)
}

func GetRateLimitingStatus(method string, route string, user string, ip string, group string) *ratelimiting.Status {
	log.Debug("Received rate limiting info",
		slog.String("method", method),
		slog.String("route", route),
		slog.String("user", user),
		slog.String("group", group),
		slog.String("ip", ip))

	return ratelimiting.ShouldRateLimitRequest(method, route, user, ip, group)
}

func OnRequestShutdown(method string, route string, statusCode int, user string, ip string, apiSpec *aikido_types.APISpec) {
	log.Debug("Received request metadata",
		slog.String("method", method),
		slog.String("route", route),
		slog.Int("statusCode", statusCode),
		slog.String("user", user),
		slog.String("ip", ip))

	stateCollector.Stats().OnRequest()
	go stateCollector.StoreRoute(method, route, apiSpec)
}

// OnUser records or updates user activity in the global user registry.
// It updates the user's name, IP address, and last seen timestamp while
// preserving the original first seen time. Safe for concurrent use.
func OnUser(id string, username string, ip string) aikido_types.User {
	log.Debug("Received user event", slog.String("id", id))
	return storeUser(id, username, ip)
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

	Stats().OnAttackDetected(attack.Attack.Blocked)
}

func OnMonitoredSinkStats(sink string, stats *aikido_types.MonitoredSinkTimings) {
	Stats().OnSinkStats(sink, stats)
}

func OnMiddlewareInstalled() {
	log.Debug("Received MiddlewareInstalled")
	stateCollector.SetMiddlewareInstalled(true)
}

func CheckAttackWave(ctx *request.Context) bool {
	return attackWaveDetector.CheckRequest(ctx)
}

type DetectedAttackWave struct {
	IPAddress string
	UserAgent string
	Source    string
}

func OnAttackWaveDetected(ctx *request.Context) {
	if ctx == nil {
		return
	}

	log.Debug("Reporting attack wave")

	requestInfo := cloud.AttackWaveRequestInfo{
		IPAddress: ctx.GetIP(),
		UserAgent: ctx.GetUserAgent(),
		Source:    ctx.Source,
	}

	metadata := map[string]string{}

	// Get samples for this IP and serialize to JSON
	samples := attackWaveDetector.GetSamplesForIP(ctx.GetIP())
	if len(samples) > 0 {
		samplesJSON, err := json.Marshal(samples)
		if err != nil {
			log.Debug("Error marshaling attack wave samples", slog.Any("error", err))
		} else {
			metadata["samples"] = string(samplesJSON)
		}
	}

	if client := GetCloudClient(); client != nil {
		client.SendAttackWaveDetectedEvent(getAgentInfo(), requestInfo, cloud.AttackWaveDetails{
			Metadata: metadata,
			User:     ctx.GetUser(),
		})
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

func State() *state.Collector {
	return stateCollector
}

func Stats() *stats.Stats {
	return stateCollector.Stats()
}
