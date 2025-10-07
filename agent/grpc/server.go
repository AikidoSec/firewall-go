package grpc

import (
	"context"
	"sync/atomic"

	"github.com/AikidoSec/firewall-go/agent/cloud"
	"github.com/AikidoSec/firewall-go/agent/globals"
	"github.com/AikidoSec/firewall-go/agent/ipc/protos"
	"github.com/AikidoSec/firewall-go/agent/log"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

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

func OnAttackDetected(ctx context.Context, req *protos.AttackDetected) (*emptypb.Empty, error) {
	cloud.SendAttackDetectedEvent(req)
	storeAttackStats(req)
	return &emptypb.Empty{}, nil
}

func OnMonitoredSinkStats(ctx context.Context, req *protos.MonitoredSinkStats) (*emptypb.Empty, error) {
	storeSinkStats(req)
	return &emptypb.Empty{}, nil
}

func OnMiddlewareInstalled(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	log.Debugf("Received MiddlewareInstalled")
	atomic.StoreUint32(&globals.MiddlewareInstalled, 1)
	return &emptypb.Empty{}, nil
}
