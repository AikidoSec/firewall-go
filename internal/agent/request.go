package agent

import (
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/apidiscovery"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
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

	mergedBodySchema := apidiscovery.MergeDataSchemas(currentBodySchema, newBodySchema)
	mergedQuerySchema := apidiscovery.MergeDataSchemas(currentQuerySchema, newQuerySchema)
	mergedAuth := apidiscovery.MergeAPIAuthTypes(currentAuth, newAuth)
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
