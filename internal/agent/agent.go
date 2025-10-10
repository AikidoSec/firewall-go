package agent

import (
	"errors"
	"sync/atomic"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/cloud"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/AikidoSec/firewall-go/internal/agent/log"
	"github.com/AikidoSec/firewall-go/internal/agent/machine"
	"github.com/AikidoSec/firewall-go/internal/agent/rate_limiting"
)

var ErrCloudConfigNotUpdated = errors.New("cloud config was not updated")

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

func OnDomain(domain string, port uint32) {
	log.Debugf("Received domain: %s:%d", domain, port)
	storeDomain(domain, port)
}

func GetRateLimitingStatus(method string, route string, user string, ip string) *aikido_types.RateLimitingStatus {
	log.Debugf("Received rate limiting info: %s %s %s %s", method, route, user, ip)

	return getRateLimitingStatus(method, route, user, ip)
}

func OnRequestShutdown(method string, route string, statusCode int, user string, ip string, apiSpec *aikido_types.APISpec) {
	log.Debugf("Received request metadata: %s %s %d %s %s %v", method, route, statusCode, user, ip, apiSpec)

	go storeStats()
	go storeRoute(method, route, apiSpec)
	go updateRateLimitingCounts(method, route, user, ip)

	atomic.StoreUint32(&globals.GotTraffic, 1)
}

func GetCloudConfig(configUpdatedAt int64) (*aikido_types.CloudConfigData, error) {
	cloudConfig := getCloudConfig(configUpdatedAt)
	if cloudConfig == nil {
		return nil, ErrCloudConfigNotUpdated
	}
	return cloudConfig, nil
}

func OnUser(id string, username string, ip string) {
	log.Debugf("Received user event: %s", id)
	onUserEvent(id, username, ip)
}

func OnAttackDetected(attack *aikido_types.DetectedAttack) {
	log.Debugf("Reporting attack")
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
