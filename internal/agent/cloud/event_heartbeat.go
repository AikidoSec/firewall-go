package cloud

import (
	"sync/atomic"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
)

func GetHostnamesAndClear() []aikido_types.Hostname {
	globals.HostnamesMutex.Lock()
	defer globals.HostnamesMutex.Unlock()

	var hostnames []aikido_types.Hostname
	for domain := range globals.Hostnames {
		for port := range globals.Hostnames[domain] {
			hostnames = append(hostnames, aikido_types.Hostname{URL: domain, Port: port, Hits: globals.Hostnames[domain][port]})
		}
	}

	globals.Hostnames = make(map[string]map[uint32]uint64)
	return hostnames
}

func GetRoutesAndClear() []aikido_types.Route {
	globals.RoutesMutex.Lock()
	defer globals.RoutesMutex.Unlock()

	var routes []aikido_types.Route
	for _, methodsMap := range globals.Routes {
		for _, routeData := range methodsMap {
			if routeData.Hits == 0 {
				continue
			}
			routes = append(routes, *routeData)
			routeData.Hits = 0
		}
	}

	// Clear routes data
	globals.Routes = make(map[string]map[string]*aikido_types.Route)
	return routes
}

func GetUsersAndClear() []aikido_types.User {
	globals.UsersMutex.Lock()
	defer globals.UsersMutex.Unlock()

	var users []aikido_types.User
	for _, user := range globals.Users {
		users = append(users, user)
	}

	globals.Users = make(map[string]aikido_types.User)
	return users
}

func GetMonitoredSinkStatsAndClear() map[string]aikido_types.MonitoredSinkStats {
	monitoredSinkStats := make(map[string]aikido_types.MonitoredSinkStats)
	for sink, stats := range globals.StatsData.MonitoredSinkTimings {
		if stats.Total <= globals.MinStatsCollectedForRelevantMetrics {
			continue
		}

		monitoredSinkStats[sink] = aikido_types.MonitoredSinkStats{
			AttacksDetected:       stats.AttacksDetected,
			InterceptorThrewError: stats.InterceptorThrewError,
			WithoutContext:        stats.WithoutContext,
			Total:                 stats.Total,
			CompressedTimings: []aikido_types.CompressedTiming{
				{
					AverageInMS:  utils.ComputeAverage(stats.Timings),
					Percentiles:  utils.ComputePercentiles(stats.Timings),
					CompressedAt: utils.GetTime(),
				},
			},
		}

		delete(globals.StatsData.MonitoredSinkTimings, sink)
	}
	return monitoredSinkStats
}

func GetStatsAndClear() aikido_types.Stats {
	globals.StatsData.StatsMutex.Lock()
	defer globals.StatsData.StatsMutex.Unlock()

	stats := aikido_types.Stats{
		Sinks:     GetMonitoredSinkStatsAndClear(),
		StartedAt: globals.StatsData.StartedAt,
		EndedAt:   utils.GetTime(),
		Requests: aikido_types.Requests{
			Total:   globals.StatsData.Requests,
			Aborted: globals.StatsData.RequestsAborted,
			AttacksDetected: aikido_types.AttacksDetected{
				Total:   globals.StatsData.Attacks,
				Blocked: globals.StatsData.AttacksBlocked,
			},
		},
	}

	globals.StatsData.StartedAt = utils.GetTime()
	globals.StatsData.Requests = 0
	globals.StatsData.RequestsAborted = 0
	globals.StatsData.Attacks = 0
	globals.StatsData.AttacksBlocked = 0

	return stats
}

func GetMiddlewareInstalled() bool {
	return atomic.LoadUint32(&globals.MiddlewareInstalled) == 1
}

func SendHeartbeatEvent() {
	heartbeatEvent := aikido_types.Heartbeat{
		Type:                "heartbeat",
		Agent:               GetAgentInfo(),
		Time:                utils.GetTime(),
		Stats:               GetStatsAndClear(),
		Hostnames:           GetHostnamesAndClear(),
		Routes:              GetRoutesAndClear(),
		Users:               GetUsersAndClear(),
		MiddlewareInstalled: GetMiddlewareInstalled(),
	}

	response, err := SendCloudRequest(globals.EnvironmentConfig.Endpoint, globals.EventsAPI, globals.EventsAPIMethod, heartbeatEvent)
	if err != nil {
		LogCloudRequestError("Error in sending heartbeat event: ", err)
		return
	}
	storeCloudConfig(response)
}
