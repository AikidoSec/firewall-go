package grpc

import (
	"context"
	"time"

	agent "github.com/AikidoSec/firewall-go/agent"
	"github.com/AikidoSec/firewall-go/agent/ipc/protos"
	"github.com/AikidoSec/firewall-go/internal/config"
	"github.com/AikidoSec/firewall-go/internal/log"
	"google.golang.org/protobuf/types/known/emptypb"
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

func OnAttackDetected(attackDetected *protos.AttackDetected) {
	log.Debugf("Reporting attack back over gRPC")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := agent.OnAttackDetected(ctx, attackDetected)
	if err != nil {
		log.Warnf("Could not send attack detected event")
		return
	}
	log.Debugf("Attack detected event sent via socket")
}

func OnMonitoredSinkStats(sink string, attacksDetected, attacksBlocked, interceptorThrewError, withoutContext, total int32, timings []int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	log.Debugf("Got stats for sink \"%s\": attacksDetected = %d, attacksBlocked = %d, interceptorThrewError = %d, withoutContext = %d, total = %d", sink, attacksDetected, attacksBlocked, interceptorThrewError, withoutContext, total)

	_, err := agent.OnMonitoredSinkStats(ctx, &protos.MonitoredSinkStats{
		Sink:                  sink,
		AttacksDetected:       attacksDetected,
		AttacksBlocked:        attacksBlocked,
		InterceptorThrewError: interceptorThrewError,
		WithoutContext:        withoutContext,
		Total:                 total,
		Timings:               timings,
	})
	if err != nil {
		log.Warnf("Could not send monitored sink stats event")
		return
	}
	log.Debugf("Monitored sink stats for sink \"%s\" sent via socket", sink)
}

func OnMiddlewareInstalled() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := agent.OnMiddlewareInstalled(ctx, &emptypb.Empty{})
	if err != nil {
		log.Warnf("Could not call OnMiddlewareInstalled")
		return
	}
	log.Debugf("OnMiddlewareInstalled sent via socket")
}
