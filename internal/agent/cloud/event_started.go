package cloud

import (
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
)

type StartEvent struct {
	Type  string    `json:"type"`
	Agent AgentInfo `json:"agent"`
	Time  int64     `json:"time"`
}

func (c *Client) SendStartEvent(agentInfo AgentInfo) {
	startedEvent := StartEvent{
		Type:  "started",
		Agent: agentInfo,
		Time:  utils.GetTime(),
	}

	response, err := c.sendCloudRequest(c.apiEndpoint, eventsAPIRoute, eventsAPIMethod, startedEvent)
	if err != nil {
		logCloudRequestError("Error in sending start event: ", err)
		return
	}
	_ = c.storeCloudConfig(response)
}
