package grpc

import (
	"context"
	"time"

	agent "github.com/AikidoSec/firewall-go/agent"
	"github.com/AikidoSec/firewall-go/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/agent/ipc/protos"
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	_, err := agent.OnDomain(ctx, &protos.Domain{Domain: domain, Port: port})
	if err != nil {
		log.Warnf("Could not send domain %v: %v", domain, err)
		return
	}

	log.Debugf("Domain sent via socket: %v:%v", domain, port)
}

// GetRateLimitingStatus send request metadata (route & method) to Aikido Agent
func GetRateLimitingStatus(method string, route string, user string, ip string, timeout time.Duration) *protos.RateLimitingStatus {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	RateLimitingStatus, err := agent.GetRateLimitingStatus(ctx, &protos.RateLimitingInfo{Method: method, Route: route, User: user, Ip: ip})
	if err != nil {
		log.Warnf("Cannot get rate limiting status %v %v: %v", method, route, err)
		return nil
	}

	log.Debugf("Rate limiting status for (%v %v) sent via socket and got reply (%v)", method, route, RateLimitingStatus)
	return RateLimitingStatus
}

// OnRequestShutdown sends request metadata (route, method & status code) to Aikido Agent
func OnRequestShutdown(method string, route string, statusCode int, user string, ip string, apiSpec *protos.APISpec) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := agent.OnRequestShutdown(ctx, &protos.RequestMetadataShutdown{Method: method, Route: route, StatusCode: int32(statusCode), User: user, Ip: ip, ApiSpec: apiSpec})
	if err != nil {
		log.Warnf("Could not send request metadata %v %v %v: %v", method, route, statusCode, err)
		return
	}

	log.Debugf("Request metadata sent via socket (%v %v %v)", method, route, statusCode)
}

func GetCloudConfig() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cloudConfig, err := agent.GetCloudConfig(ctx, &protos.CloudConfigUpdatedAt{ConfigUpdatedAt: config.GetCloudConfigUpdatedAt()})
	if err != nil {
		log.Infof("Could not get cloud config: %v", err)
		return
	}

	log.Debugf("Got cloud config: %v", cloudConfig)
	setCloudConfig(cloudConfig)
}

func OnUserEvent(id string, username string, ip string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := agent.OnUser(ctx, &protos.User{Id: id, Username: username, Ip: ip})
	if err != nil {
		log.Warnf("Could not send user event %v %v %v: %v", id, username, ip, err)
		return
	}

	log.Debugf("User event sent via socket (%v %v %v)", id, username, ip)
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
