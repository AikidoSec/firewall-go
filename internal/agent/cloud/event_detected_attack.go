package cloud

import (
	"log/slog"
	"sync"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
	"github.com/AikidoSec/firewall-go/internal/log"
)

var (
	// Holds times at which attacks were reported
	// This allows us to limit the maximum number of attacks reported within a window of time
	attackDetectedEventsSentAt      []int64
	attackDetectedEventsSentAtMutex sync.Mutex
)

func ShouldSendAttackDetectedEvent() bool {
	attackDetectedEventsSentAtMutex.Lock()
	defer attackDetectedEventsSentAtMutex.Unlock()

	currentTime := utils.GetTime()

	// Filter out events that are outside the current interval
	var filteredEvents []int64
	for _, eventTime := range attackDetectedEventsSentAt {
		if eventTime > currentTime-globals.AttackDetectedEventsIntervalInMs {
			filteredEvents = append(filteredEvents, eventTime)
		}
	}
	attackDetectedEventsSentAt = filteredEvents

	if len(attackDetectedEventsSentAt) >= globals.MaxAttackDetectedEventsPerInterval {
		log.Warn("Maximum number of \"detected_attack\" events exceeded for timeframe",
			slog.Int("max", globals.MaxAttackDetectedEventsPerInterval),
			slog.Int("count", len(attackDetectedEventsSentAt)),
			slog.Int("interval_ms", globals.AttackDetectedEventsIntervalInMs))

		return false
	}

	attackDetectedEventsSentAt = append(attackDetectedEventsSentAt, currentTime)
	return true
}

func SendAttackDetectedEvent(attack *aikido_types.DetectedAttack) {
	if !ShouldSendAttackDetectedEvent() {
		return
	}
	detectedAttackEvent := aikido_types.DetectedAttack{
		Type:    "detected_attack",
		Agent:   GetAgentInfo(),
		Request: attack.Request,
		Attack:  attack.Attack,
		Time:    utils.GetTime(),
	}

	_, err := SendCloudRequest(globals.EnvironmentConfig.Endpoint, globals.EventsAPI, globals.EventsAPIMethod, detectedAttackEvent)
	if err != nil {
		LogCloudRequestError("Error in sending detected attack event: ", err)
		return
	}
}
