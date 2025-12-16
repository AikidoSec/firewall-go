package cloud

import (
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
)

type DetectedAttackWaveEvent struct {
	Type    string                `json:"type"`
	Request AttackWaveRequestInfo `json:"request"`
	Attack  AttackWaveDetails     `json:"attack"`
	Agent   AgentInfo             `json:"agent"`
	Time    int64                 `json:"time"`
}

type AttackWaveDetails struct {
	Metadata map[string]string  `json:"metadata"`
	User     *aikido_types.User `json:"user"`
}

type AttackWaveRequestInfo struct {
	IPAddress string `json:"ipAddress"`
	UserAgent string `json:"userAgent"`
	Source    string `json:"source"`
}

func (c *Client) SendAttackWaveDetectedEvent(agentInfo AgentInfo, request AttackWaveRequestInfo, attack AttackWaveDetails) {
	detectedAttackWaveEvent := DetectedAttackWaveEvent{
		Type:    "detected_attack_wave",
		Agent:   agentInfo,
		Request: request,
		Attack:  attack,
		Time:    utils.GetTime(),
	}

	_, err := c.sendCloudRequest(c.apiEndpoint, eventsAPIRoute, eventsAPIMethod, detectedAttackWaveEvent)
	if err != nil {
		logCloudRequestError("Error in sending detected attack wave event: ", err)
		return
	}
}
