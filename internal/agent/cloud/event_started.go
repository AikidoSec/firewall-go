package cloud

import (
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
)

func (c *Client) SendStartEvent(agentInfo aikido_types.AgentInfo) {
	startedEvent := aikido_types.Started{
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
