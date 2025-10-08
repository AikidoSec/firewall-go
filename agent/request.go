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

func getAPISpecData(apiSpec *aikido_types.APISpec) (*aikido_types.DataSchema, string, *aikido_types.DataSchema, []*aikido_types.APIAuthType) {
	if apiSpec == nil {
		return nil, "", nil, nil
	}

	var bodyDataSchema *aikido_types.DataSchema = nil
	bodyType := ""
	if apiSpec.Body != nil {
		bodyDataSchema = apiSpec.Body.Schema
		bodyType = apiSpec.Body.Type
	}

	return bodyDataSchema, bodyType, apiSpec.Query, apiSpec.Auth
}

func getMergedAPISpec(currentAPISpec *aikido_types.APISpec, newAPISpec *aikido_types.APISpec) *aikido_types.APISpec {
	if newAPISpec == nil {
		return currentAPISpec
	}
	if currentAPISpec == nil {
		return newAPISpec
	}

	currentBodySchema, currentBodyType, currentQuerySchema, currentAuth := getAPISpecData(currentAPISpec)
	newBodySchema, newBodyType, newQuerySchema, newAuth := getAPISpecData(newAPISpec)

	mergedBodySchema := api_discovery.MergeDataSchemas(currentBodySchema, newBodySchema)
	mergedQuerySchema := api_discovery.MergeDataSchemas(currentQuerySchema, newQuerySchema)
	mergedAuth := api_discovery.MergeAPIAuthTypes(currentAuth, newAuth)
	if mergedBodySchema == nil && mergedQuerySchema == nil && mergedAuth == nil {
		return nil
	}

	mergedBodyType := newBodyType
	if mergedBodyType == "" {
		mergedBodyType = currentBodyType
	}

	return &aikido_types.APISpec{
		Body: &aikido_types.APIBodyInfo{
			Type:   mergedBodyType,
			Schema: mergedBodySchema,
		},
		Query: mergedQuerySchema,
		Auth:  mergedAuth,
	}
}

func storeRoute(method string, route string, apiSpec *aikido_types.APISpec) {
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
	routeData.APISpec = getMergedAPISpec(routeData.APISpec, apiSpec)
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

func getCloudConfig(configUpdatedAt int64) *aikido_types.CloudConfigData {
	globals.CloudConfigMutex.Lock()
	defer globals.CloudConfigMutex.Unlock()

	if globals.CloudConfig.ConfigUpdatedAt <= configUpdatedAt {
		log.Debugf("CloudConfig.ConfigUpdatedAt was not updated... Returning nil!")
		return nil
	}

	var cloudBlockingEnabled *bool
	if globals.CloudConfig.Block != nil {
		block := *globals.CloudConfig.Block
		cloudBlockingEnabled = &block
	}

	cloudConfig := &aikido_types.CloudConfigData{
		ConfigUpdatedAt:   globals.CloudConfig.ConfigUpdatedAt,
		BlockedUserIds:    globals.CloudConfig.BlockedUserIds,
		BypassedIPs:       globals.CloudConfig.BypassedIPs,
		BlockedIPsList:    map[string]aikido_types.IPBlocklist{},
		BlockedUserAgents: globals.CloudConfig.BlockedUserAgents,
		Block:             cloudBlockingEnabled,
	}

	for ipBlocklistSource, ipBlocklist := range globals.CloudConfig.BlockedIPsList {
		cloudConfig.BlockedIPsList[ipBlocklistSource] = aikido_types.IPBlocklist{
			Description: ipBlocklist.Description,
			Ips:         ipBlocklist.Ips,
		}
	}

	for _, endpoint := range globals.CloudConfig.Endpoints {
		cloudConfig.Endpoints = append(cloudConfig.Endpoints, aikido_types.Endpoint{
			Method:             endpoint.Method,
			Route:              endpoint.Route,
			ForceProtectionOff: endpoint.ForceProtectionOff,
			AllowedIPAddresses: endpoint.AllowedIPAddresses,
			RateLimiting: aikido_types.RateLimiting{
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
