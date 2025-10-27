package cloud

import (
	"encoding/json"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
)

func (c *Client) CheckConfigUpdatedAt() {
	response, err := c.sendCloudRequest(globals.EnvironmentConfig.ConfigEndpoint, globals.ConfigUpdatedAtAPI, globals.ConfigUpdatedAtMethod, nil)
	if err != nil {
		logCloudRequestError("Error in sending polling config request: ", err)
		return
	}

	cloudConfigUpdatedAt := aikido_types.CloudConfigUpdatedAt{}
	err = json.Unmarshal(response, &cloudConfigUpdatedAt)
	if err != nil {
		return
	}

	if cloudConfigUpdatedAt.ConfigUpdatedAt <= config.GetCloudConfigUpdatedAt() {
		return
	}

	configResponse, err := c.sendCloudRequest(globals.EnvironmentConfig.Endpoint, globals.ConfigAPI, globals.ConfigAPIMethod, nil)
	if err != nil {
		logCloudRequestError("Error in sending config request: ", err)
		return
	}

	c.storeCloudConfig(configResponse)
}
