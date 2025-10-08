package agent

import (
	"github.com/AikidoSec/firewall-go/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/agent/api_discovery"
	"github.com/AikidoSec/firewall-go/agent/globals"
	"github.com/AikidoSec/firewall-go/agent/ipc/protos"
	"github.com/AikidoSec/firewall-go/agent/log"
	"github.com/AikidoSec/firewall-go/agent/utils"
)

func storeStats() {
	globals.StatsData.StatsMutex.Lock()
	defer globals.StatsData.StatsMutex.Unlock()

	globals.StatsData.Requests += 1
}

func storeAttackStats(blocked bool) {
	globals.StatsData.StatsMutex.Lock()
	defer globals.StatsData.StatsMutex.Unlock()

	globals.StatsData.Attacks += 1
	if blocked {
		globals.StatsData.AttacksBlocked += 1
	}
}

func storeSinkStats(sink string, stats *aikido_types.MonitoredSinkTimings) {
	globals.StatsData.StatsMutex.Lock()
	defer globals.StatsData.StatsMutex.Unlock()

	monitoredSinkTimings, found := globals.StatsData.MonitoredSinkTimings[sink]
	if !found {
		monitoredSinkTimings = aikido_types.MonitoredSinkTimings{}
	}

	monitoredSinkTimings.AttacksDetected.Total += int(stats.AttacksDetected.Total)
	monitoredSinkTimings.AttacksDetected.Blocked += int(stats.AttacksDetected.Blocked)
	monitoredSinkTimings.InterceptorThrewError += int(stats.InterceptorThrewError)
	monitoredSinkTimings.WithoutContext += int(stats.WithoutContext)
	monitoredSinkTimings.Total += int(stats.Total)
	monitoredSinkTimings.Timings = append(monitoredSinkTimings.Timings, stats.Timings...)

	globals.StatsData.MonitoredSinkTimings[sink] = monitoredSinkTimings
}

func getApiSpecData(apiSpec *protos.APISpec) (*protos.DataSchema, string, *protos.DataSchema, []*protos.APIAuthType) {
	if apiSpec == nil {
		return nil, "", nil, nil
	}

	var bodyDataSchema *protos.DataSchema = nil
	var bodyType string = ""
	if apiSpec.Body != nil {
		bodyDataSchema = apiSpec.Body.Schema
		bodyType = apiSpec.Body.Type
	}

	return bodyDataSchema, bodyType, apiSpec.Query, apiSpec.Auth
}

func getMergedApiSpec(currentApiSpec *protos.APISpec, newApiSpec *protos.APISpec) *protos.APISpec {
	if newApiSpec == nil {
		return currentApiSpec
	}
	if currentApiSpec == nil {
		return newApiSpec
	}

	currentBodySchema, currentBodyType, currentQuerySchema, currentAuth := getApiSpecData(currentApiSpec)
	newBodySchema, newBodyType, newQuerySchema, newAuth := getApiSpecData(newApiSpec)

	mergedBodySchema := api_discovery.MergeDataSchemas(currentBodySchema, newBodySchema)
	mergedQuerySchema := api_discovery.MergeDataSchemas(currentQuerySchema, newQuerySchema)
	mergedAuth := api_discovery.MergeApiAuthTypes(currentAuth, newAuth)
	if mergedBodySchema == nil && mergedQuerySchema == nil && mergedAuth == nil {
		return nil
	}

	mergedBodyType := newBodyType
	if mergedBodyType == "" {
		mergedBodyType = currentBodyType
	}

	return &protos.APISpec{
		Body: &protos.APIBodyInfo{
			Type:   mergedBodyType,
			Schema: mergedBodySchema,
		},
		Query: mergedQuerySchema,
		Auth:  mergedAuth,
	}
}

func storeRoute(method string, route string, apiSpec *protos.APISpec) {
	globals.RoutesMutex.Lock()
	defer globals.RoutesMutex.Unlock()

	if _, ok := globals.Routes[route]; !ok {
		globals.Routes[route] = make(map[string]*aikido_types.Route)
	}
	routeData, ok := globals.Routes[route][method]
	if !ok {
		routeData = &aikido_types.Route{Path: route, Method: method}
		globals.Routes[route][method] = routeData
	}

	routeData.Hits++
	routeData.ApiSpec = getMergedApiSpec(routeData.ApiSpec, apiSpec)
}

func incrementRateLimitingCounts(m map[string]*aikido_types.RateLimitingCounts, key string) {
	if key == "" {
		return
	}

	rateLimitingData, exists := m[key]
	if !exists {
		rateLimitingData = &aikido_types.RateLimitingCounts{}
		m[key] = rateLimitingData
	}

	rateLimitingData.TotalNumberOfRequests += 1
	rateLimitingData.NumberOfRequestsPerWindow.IncrementLast()
}

func updateRateLimitingCounts(method string, route string, user string, ip string) {
	globals.RateLimitingMutex.Lock()
	defer globals.RateLimitingMutex.Unlock()

	rateLimitingData, exists := globals.RateLimitingMap[aikido_types.RateLimitingKey{Method: method, Route: route}]
	if !exists {
		return
	}

	incrementRateLimitingCounts(rateLimitingData.UserCounts, user)
	incrementRateLimitingCounts(rateLimitingData.IpCounts, ip)
}

func isRateLimitingThresholdExceeded(config *aikido_types.RateLimitingConfig, countsMap map[string]*aikido_types.RateLimitingCounts, key string) bool {
	counts, exists := countsMap[key]
	if !exists {
		return false
	}

	return counts.TotalNumberOfRequests >= config.MaxRequests
}

func getRateLimitingStatus(method string, route string, user string, ip string) *aikido_types.RateLimitingStatus {
	globals.RateLimitingMutex.RLock()
	defer globals.RateLimitingMutex.RUnlock()

	rateLimitingDataForRoute, exists := globals.RateLimitingMap[aikido_types.RateLimitingKey{Method: method, Route: route}]
	if !exists {
		return &aikido_types.RateLimitingStatus{Block: false}
	}

	if user != "" {
		// If the user exists, we only try to rate limit by user
		if isRateLimitingThresholdExceeded(&rateLimitingDataForRoute.Config, rateLimitingDataForRoute.UserCounts, user) {
			log.Infof("Rate limited request for user %s - %s %s - %v", user, method, route, rateLimitingDataForRoute.UserCounts[user])
			return &aikido_types.RateLimitingStatus{Block: true, Trigger: "user"}
		}
	} else {
		// Otherwise, we rate limit by ip
		if isRateLimitingThresholdExceeded(&rateLimitingDataForRoute.Config, rateLimitingDataForRoute.IpCounts, ip) {
			log.Infof("Rate limited request for ip %s - %s %s - %v", ip, method, route, rateLimitingDataForRoute.IpCounts[ip])
			return &aikido_types.RateLimitingStatus{Block: true, Trigger: "ip"}
		}
	}

	return &aikido_types.RateLimitingStatus{Block: false}
}

func getCloudConfig(configUpdatedAt int64) *protos.CloudConfig {
	isBlockingEnabled := utils.IsBlockingEnabled()

	globals.CloudConfigMutex.Lock()
	defer globals.CloudConfigMutex.Unlock()

	if globals.CloudConfig.ConfigUpdatedAt <= configUpdatedAt {
		log.Debugf("CloudConfig.ConfigUpdatedAt was not updated... Returning nil!")
		return nil
	}

	cloudConfig := &protos.CloudConfig{
		ConfigUpdatedAt:   globals.CloudConfig.ConfigUpdatedAt,
		BlockedUserIds:    globals.CloudConfig.BlockedUserIds,
		BypassedIps:       globals.CloudConfig.BypassedIps,
		BlockedIps:        map[string]*protos.IpBlockList{},
		BlockedUserAgents: globals.CloudConfig.BlockedUserAgents,
		Block:             isBlockingEnabled,
	}

	for ipBlocklistSource, ipBlocklist := range globals.CloudConfig.BlockedIpsList {
		cloudConfig.BlockedIps[ipBlocklistSource] = &protos.IpBlockList{
			Description: ipBlocklist.Description,
			Ips:         ipBlocklist.Ips,
		}
	}

	for _, endpoint := range globals.CloudConfig.Endpoints {
		cloudConfig.Endpoints = append(cloudConfig.Endpoints, &protos.Endpoint{
			Method:             endpoint.Method,
			Route:              endpoint.Route,
			ForceProtectionOff: endpoint.ForceProtectionOff,
			AllowedIPAddresses: endpoint.AllowedIPAddresses,
			RateLimiting: &protos.RateLimiting{
				Enabled: endpoint.RateLimiting.Enabled,
			},
		})
	}

	return cloudConfig
}

func onUserEvent(id string, username string, ip string) {
	globals.UsersMutex.Lock()
	defer globals.UsersMutex.Unlock()

	if _, exists := globals.Users[id]; exists {
		globals.Users[id] = aikido_types.User{
			ID:            id,
			Name:          username,
			LastIpAddress: ip,
			FirstSeenAt:   globals.Users[id].FirstSeenAt,
			LastSeenAt:    utils.GetTime(),
		}
		return
	}

	globals.Users[id] = aikido_types.User{
		ID:            id,
		Name:          username,
		LastIpAddress: ip,
		FirstSeenAt:   utils.GetTime(),
		LastSeenAt:    utils.GetTime(),
	}
}
