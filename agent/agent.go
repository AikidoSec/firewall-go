package agent

import (
	"context"
	"sync/atomic"

	"github.com/AikidoSec/firewall-go/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/agent/cloud"
	"github.com/AikidoSec/firewall-go/agent/config"
	"github.com/AikidoSec/firewall-go/agent/globals"
	"github.com/AikidoSec/firewall-go/agent/ipc/protos"
	"github.com/AikidoSec/firewall-go/agent/log"
	"github.com/AikidoSec/firewall-go/agent/machine"
	"github.com/AikidoSec/firewall-go/agent/rate_limiting"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func Init(initJSON string) (initOk bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Warn("Recovered from panic:", r)
			initOk = false
		}
	}()

	log.Init()
	machine.Init()
	if !config.Init(initJSON) {
		return false
	}

	cloud.Init()
	rate_limiting.Init()

	log.Infof("Aikido Agent v%s loaded!", globals.EnvironmentConfig.Version)
	return true
}

func AgentUninit() {
	rate_limiting.Uninit()
	cloud.Uninit()
	config.Uninit()

	log.Infof("Aikido Agent v%s unloaded!", globals.EnvironmentConfig.Version)
	log.Uninit()
}

func OnDomain(ctx context.Context, req *protos.Domain) (*emptypb.Empty, error) {
	log.Debugf("Received domain: %s:%d", req.GetDomain(), req.GetPort())
	storeDomain(req.GetDomain(), req.GetPort())
	return &emptypb.Empty{}, nil
}

func GetRateLimitingStatus(ctx context.Context, req *protos.RateLimitingInfo) (*protos.RateLimitingStatus, error) {
	log.Debugf("Received rate limiting info: %s %s %s %s", req.GetMethod(), req.GetRoute(), req.GetUser(), req.GetIp())

	return getRateLimitingStatus(req.GetMethod(), req.GetRoute(), req.GetUser(), req.GetIp()), nil
}

func OnRequestShutdown(ctx context.Context, req *protos.RequestMetadataShutdown) (*emptypb.Empty, error) {
	log.Debugf("Received request metadata: %s %s %d %s %s %v", req.GetMethod(), req.GetRoute(), req.GetStatusCode(), req.GetUser(), req.GetIp(), req.GetApiSpec())

	go storeStats()
	go storeRoute(req.GetMethod(), req.GetRoute(), req.GetApiSpec())
	go updateRateLimitingCounts(req.GetMethod(), req.GetRoute(), req.GetUser(), req.GetIp())

	atomic.StoreUint32(&globals.GotTraffic, 1)
	return &emptypb.Empty{}, nil
}

func GetCloudConfig(ctx context.Context, req *protos.CloudConfigUpdatedAt) (*protos.CloudConfig, error) {
	cloudConfig := getCloudConfig(req.GetConfigUpdatedAt())
	if cloudConfig == nil {
		return nil, status.Errorf(codes.Canceled, "CloudConfig was not updated")
	}
	return cloudConfig, nil
}

func OnUser(ctx context.Context, req *protos.User) (*emptypb.Empty, error) {
	log.Debugf("Received user event: %s", req.GetId())
	go onUserEvent(req.GetId(), req.GetUsername(), req.GetIp())
	return &emptypb.Empty{}, nil
}

func OnAttackDetected(attack *aikido_types.DetectedAttack) {
	cloud.SendAttackDetectedEvent(attack)
	storeAttackStats(attack.Attack.Blocked)
}

func OnMonitoredSinkStats(sink string, stats *aikido_types.MonitoredSinkTimings) {
	storeSinkStats(sink, stats)
}

func OnMiddlewareInstalled() {
	log.Debugf("Received MiddlewareInstalled")
	atomic.StoreUint32(&globals.MiddlewareInstalled, 1)
}
