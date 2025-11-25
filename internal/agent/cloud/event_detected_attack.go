package cloud

import (
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
)

type DetectedAttackEvent struct {
	Type    string                     `json:"type"`
	Request aikido_types.RequestInfo   `json:"request"`
	Attack  aikido_types.AttackDetails `json:"attack"`
	Agent   AgentInfo                  `json:"agent"`
	Time    int64                      `json:"time"`
}

func (c *Client) SendAttackDetectedEvent(agentInfo AgentInfo, request aikido_types.RequestInfo, attack aikido_types.AttackDetails) {
	if !shouldSendAttackEvent() {
		return
	}
	detectedAttackEvent := DetectedAttackEvent{
		Type:    "detected_attack",
		Agent:   agentInfo,
		Request: request,
		Attack:  attack,
		Time:    utils.GetTime(),
	}

	_, err := c.sendCloudRequest(c.apiEndpoint, eventsAPIRoute, eventsAPIMethod, detectedAttackEvent)
	if err != nil {
		logCloudRequestError("Error in sending detected attack event: ", err)
		return
	}
}
