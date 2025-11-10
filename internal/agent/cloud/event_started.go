package cloud

import (
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
)

type StartEvent struct {
	Type  string    `json:"type"`
	Agent AgentInfo `json:"agent"`
	Time  int64     `json:"time"`
}

func (c *Client) SendStartEvent(agentInfo AgentInfo) (*aikido_types.CloudConfigData, error) {
	startedEvent := StartEvent{
		Type:  "started",
		Agent: agentInfo,
		Time:  utils.GetTime(),
	}

	response, err := c.sendCloudRequest(c.apiEndpoint, eventsAPIRoute, eventsAPIMethod, startedEvent)
	if err != nil {
		logCloudRequestError("Error in sending start event: ", err)
		return nil, err
	}

	return parseCloudConfigResponse(response)
}
