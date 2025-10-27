package cloud

import (
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
)

var (
	heartbeatRoutineChannel     = make(chan struct{})
	heartBeatTicker             = time.NewTicker(10 * time.Minute)
	configPollingRoutineChannel = make(chan struct{})
	configPollingTicker         = time.NewTicker(1 * time.Minute)
)

func StartPolling(client *Client) {
	utils.StartPollingRoutine(heartbeatRoutineChannel, heartBeatTicker, client.SendHeartbeatEvent)
	utils.StartPollingRoutine(configPollingRoutineChannel, configPollingTicker, client.CheckConfigUpdatedAt)

	globals.StatsData.StartedAt = utils.GetTime()
	globals.StatsData.MonitoredSinkTimings = make(map[string]aikido_types.MonitoredSinkTimings)
}

func StopPolling() {
	utils.StopPollingRoutine(heartbeatRoutineChannel)
	utils.StopPollingRoutine(configPollingRoutineChannel)
}
