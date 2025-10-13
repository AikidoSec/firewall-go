package cloud

import (
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
)

var (
	HeartbeatRoutineChannel     = make(chan struct{})
	HeartBeatTicker             = time.NewTicker(10 * time.Minute)
	ConfigPollingRoutineChannel = make(chan struct{})
	ConfigPollingTicker         = time.NewTicker(1 * time.Minute)
)

func Init() {
	SendStartEvent()
	utils.StartPollingRoutine(HeartbeatRoutineChannel, HeartBeatTicker, SendHeartbeatEvent)
	utils.StartPollingRoutine(ConfigPollingRoutineChannel, ConfigPollingTicker, CheckConfigUpdatedAt)

	globals.StatsData.StartedAt = utils.GetTime()
	globals.StatsData.MonitoredSinkTimings = make(map[string]aikido_types.MonitoredSinkTimings)
}

func Uninit() {
	utils.StopPollingRoutine(HeartbeatRoutineChannel)
	utils.StopPollingRoutine(ConfigPollingRoutineChannel)
}
