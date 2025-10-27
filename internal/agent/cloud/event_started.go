package cloud

import (
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
)

func (c *Client) SendStartEvent() {
	startedEvent := aikido_types.Started{
		Type:  "started",
		Agent: getAgentInfo(),
		Time:  utils.GetTime(),
	}

	response, err := c.sendCloudRequest(c.apiEndpoint, globals.EventsAPI, globals.EventsAPIMethod, startedEvent)
	if err != nil {
		logCloudRequestError("Error in sending start event: ", err)
		return
	}
	c.storeCloudConfig(response)
}
