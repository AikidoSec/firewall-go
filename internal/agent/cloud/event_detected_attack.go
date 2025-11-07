package cloud

import (
	"log/slog"
	"sync"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
	"github.com/AikidoSec/firewall-go/internal/log"
)

var (
	// Holds times at which attacks were reported
	// This allows us to limit the maximum number of attacks reported within a window of time
	attackDetectedEventsSentAt      []int64
	attackDetectedEventsSentAtMutex sync.Mutex
)

const (
	maxAttackDetectedEventsPerInterval = 100
	attackDetectedEventsIntervalInMs   = 60 * 60 * 1000 // 1 hour
)

func shouldSendAttackDetectedEvent() bool {
	attackDetectedEventsSentAtMutex.Lock()
	defer attackDetectedEventsSentAtMutex.Unlock()

	currentTime := utils.GetTime()

	// Filter out events that are outside the current interval
	var filteredEvents []int64
	for _, eventTime := range attackDetectedEventsSentAt {
		if eventTime > currentTime-attackDetectedEventsIntervalInMs {
			filteredEvents = append(filteredEvents, eventTime)
		}
	}
	attackDetectedEventsSentAt = filteredEvents

	if len(attackDetectedEventsSentAt) >= maxAttackDetectedEventsPerInterval {
		log.Warn("Maximum number of \"detected_attack\" events exceeded for timeframe",
			slog.Int("max", maxAttackDetectedEventsPerInterval),
			slog.Int("count", len(attackDetectedEventsSentAt)),
			slog.Int("interval_ms", attackDetectedEventsIntervalInMs))

		return false
	}

	attackDetectedEventsSentAt = append(attackDetectedEventsSentAt, currentTime)
	return true
}

func (c *Client) SendAttackDetectedEvent(agentInfo aikido_types.AgentInfo, attack *aikido_types.DetectedAttack) {
	if !shouldSendAttackDetectedEvent() {
		return
	}
	detectedAttackEvent := aikido_types.DetectedAttack{
		Type:    "detected_attack",
		Agent:   agentInfo,
		Request: attack.Request,
		Attack:  attack.Attack,
		Time:    utils.GetTime(),
	}

	_, err := c.sendCloudRequest(c.apiEndpoint, eventsAPIRoute, eventsAPIMethod, detectedAttackEvent)
	if err != nil {
		logCloudRequestError("Error in sending detected attack event: ", err)
		return
	}
}
