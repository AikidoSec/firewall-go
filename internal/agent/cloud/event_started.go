package cloud

import (
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/packages"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
)

type StartEvent struct {
	Type     string                     `json:"type"`
	Agent    AgentInfo                  `json:"agent"`
	Time     int64                      `json:"time"`
	Packages []aikido_types.PackageInfo `json:"packages"`
}

func (c *Client) SendStartEvent(agentInfo AgentInfo) (*aikido_types.CloudConfigData, error) {
	startedEvent := StartEvent{
		Type:     "started",
		Agent:    agentInfo,
		Time:     utils.GetTime(),
		Packages: packages.Get(),
	}

	response, err := c.sendCloudRequest(c.apiEndpoint, eventsAPIRoute, eventsAPIMethod, startedEvent)
	if err != nil {
		return nil, err
	}

	return parseCloudConfigResponse(response)
}
