package grpc

import (
	agent "github.com/AikidoSec/firewall-go/agent"
	"github.com/AikidoSec/firewall-go/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/config"
	"github.com/AikidoSec/firewall-go/internal/log"
)

func Init() {
	startCloudConfigRoutine()
}

func Uninit() {
	stopCloudConfigRoutine()
}

// OnDomain sends outgoing domain to Aikido Agent
func OnDomain(domain string, port uint32) {
	agent.OnDomain(domain, port)
}

// GetRateLimitingStatus send request metadata (route & method) to Aikido Agent
func GetRateLimitingStatus(method string, route string, user string, ip string) *aikido_types.RateLimitingStatus {
	return agent.GetRateLimitingStatus(method, route, user, ip)
}

// OnRequestShutdown sends request metadata (route, method & status code) to Aikido Agent
func OnRequestShutdown(method string, route string, statusCode int, user string, ip string, apiSpec *aikido_types.APISpec) {
	agent.OnRequestShutdown(method, route, statusCode, user, ip, apiSpec)
}

func GetCloudConfig() {
	cloudConfig, err := agent.GetCloudConfig(config.GetCloudConfigUpdatedAt())
	if err != nil {
		log.Infof("Could not get cloud config: %v", err)
		return
	}

	log.Debugf("Got cloud config: %v", cloudConfig)
	setCloudConfig(cloudConfig)
}

func OnUserEvent(id string, username string, ip string) {
	agent.OnUser(id, username, ip)
}

func OnAttackDetected(attackDetected *aikido_types.DetectedAttack) {
	log.Debugf("Reporting attack")

	agent.OnAttackDetected(attackDetected)
}

func OnMonitoredSinkStats(sink string, attacksDetected, attacksBlocked, interceptorThrewError, withoutContext, total int, timings []int64) {
	log.Debugf("Got stats for sink \"%s\": attacksDetected = %d, attacksBlocked = %d, interceptorThrewError = %d, withoutContext = %d, total = %d", sink, attacksDetected, attacksBlocked, interceptorThrewError, withoutContext, total)

	agent.OnMonitoredSinkStats(sink, &aikido_types.MonitoredSinkTimings{
		AttacksDetected: aikido_types.AttacksDetected{
			Total:   attacksDetected,
			Blocked: attacksBlocked,
		},
		InterceptorThrewError: interceptorThrewError,
		WithoutContext:        withoutContext,
		Total:                 total,
		Timings:               timings,
	})
}

func OnMiddlewareInstalled() {
	agent.OnMiddlewareInstalled()
}
