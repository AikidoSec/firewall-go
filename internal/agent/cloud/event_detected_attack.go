package cloud

import (
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/AikidoSec/firewall-go/internal/agent/log"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
)

func ShouldSendAttackDetectedEvent() bool {
	globals.AttackDetectedEventsSentAtMutex.Lock()
	defer globals.AttackDetectedEventsSentAtMutex.Unlock()

	currentTime := utils.GetTime()

	// Filter out events that are outside the current interval
	var filteredEvents []int64
	for _, eventTime := range globals.AttackDetectedEventsSentAt {
		if eventTime > currentTime-globals.AttackDetectedEventsIntervalInMs {
			filteredEvents = append(filteredEvents, eventTime)
		}
	}
	globals.AttackDetectedEventsSentAt = filteredEvents

	if len(globals.AttackDetectedEventsSentAt) >= globals.MaxAttackDetectedEventsPerInterval {
		log.Warnf("Maximum (%d) number of \"detected_attack\" events exceeded for timeframe: %d / %d ms",
			globals.MaxAttackDetectedEventsPerInterval, len(globals.AttackDetectedEventsSentAt), globals.AttackDetectedEventsIntervalInMs)
		return false
	}

	globals.AttackDetectedEventsSentAt = append(globals.AttackDetectedEventsSentAt, currentTime)
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

	response, err := SendCloudRequest(globals.EnvironmentConfig.Endpoint, globals.EventsAPI, globals.EventsAPIMethod, detectedAttackEvent)
	if err != nil {
		LogCloudRequestError("Error in sending detected attack event: ", err)
		return
	}

	StoreCloudConfig(response)
}
