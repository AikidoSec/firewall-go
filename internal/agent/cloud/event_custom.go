package cloud

import (
	"context"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
)

type CustomEvent struct {
	Type    string                   `json:"type"`
	Name    string                   `json:"name"`
	Request aikido_types.RequestInfo `json:"request"`
	Agent   AgentInfo                `json:"agent"`
	User    *aikido_types.User       `json:"user,omitempty"`
	Time    int64                    `json:"time"`
}

func (c *Client) SendCustomEvent(agentInfo AgentInfo, request aikido_types.RequestInfo, name string, user *aikido_types.User) {
	customEvent := CustomEvent{
		Type:    "custom",
		Name:    name,
		Agent:   agentInfo,
		Request: request,
		User:    user,
		Time:    utils.GetTime(),
	}

	_, err := c.sendCloudRequest(context.Background(), c.apiEndpoint, eventsAPIRoute, eventsAPIMethod, customEvent)
	if err != nil {
		logCloudRequestError("Error in sending custom event: ", err)
		return
	}
}
