package cloud

import (
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/state/stats"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
)

type HeartbeatEvent struct {
	Type                string                  `json:"type"`
	Stats               stats.Data              `json:"stats"`
	Hostnames           []aikido_types.Hostname `json:"hostnames"`
	Routes              []aikido_types.Route    `json:"routes"`
	Users               []aikido_types.User     `json:"users"`
	Agent               AgentInfo               `json:"agent"`
	Time                int64                   `json:"time"`
	MiddlewareInstalled bool                    `json:"middlewareInstalled"`
}

type HeartbeatData struct {
	Hostnames           []aikido_types.Hostname
	Routes              []aikido_types.Route
	Users               []aikido_types.User
	Stats               stats.Data
	MiddlewareInstalled bool
}

// SendHeartbeatEvent sends a heartbeat to the cloud and returns the latest configuration.
func (c *Client) SendHeartbeatEvent(agentInfo AgentInfo, data HeartbeatData) (*aikido_types.CloudConfigData, error) {
	heartbeatEvent := HeartbeatEvent{
		Type:                "heartbeat",
		Agent:               agentInfo,
		Time:                utils.GetTime(),
		Stats:               data.Stats,
		Hostnames:           data.Hostnames,
		Routes:              data.Routes,
		Users:               data.Users,
		MiddlewareInstalled: data.MiddlewareInstalled,
	}

	response, err := c.sendCloudRequest(c.apiEndpoint, eventsAPIRoute, eventsAPIMethod, heartbeatEvent)
	if err != nil {
		logCloudRequestError("Error in sending heartbeat event: ", err)
		return nil, err
	}

	return parseCloudConfigResponse(response)
}
