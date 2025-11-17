package agent

import (
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
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
