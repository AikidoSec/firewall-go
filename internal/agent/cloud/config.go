package cloud

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/log"
)

const (
	configUpdatedAtMethod   = "GET"
	configUpdatedAtAPIRoute = "/config"
	configAPIMethod         = "GET"
	configAPIRoute          = "/api/runtime/config"
	listsAPIMethod          = "GET"
	listsAPIRoute           = "/api/runtime/firewall/lists"
)

var ErrParsingConfig = errors.New("failed to parse cloud config")

// FetchConfigUpdatedAt returns the time at which the cloud config was last updated
func (c *Client) FetchConfigUpdatedAt() time.Time {
	response, err := c.sendCloudRequest(c.realtimeEndpoint, configUpdatedAtAPIRoute, configUpdatedAtMethod, nil)
	if err != nil {
		logCloudRequestError("Error in sending polling config request: ", err)
		return time.Time{}
	}

	cloudConfigUpdatedAt := aikido_types.CloudConfigUpdatedAt{}
	err = json.Unmarshal(response, &cloudConfigUpdatedAt)
	if err != nil {
		return time.Time{}
	}

	return time.UnixMilli(cloudConfigUpdatedAt.ConfigUpdatedAt)
}

func (c *Client) FetchConfig() (*aikido_types.CloudConfigData, error) {
	configResponse, err := c.sendCloudRequest(c.apiEndpoint, configAPIRoute, configAPIMethod, nil)
	if err != nil {
		logCloudRequestError("Error in sending config request: ", err)
		return nil, err
	}

	return parseCloudConfigResponse(configResponse)
}

func parseCloudConfigResponse(resp []byte) (*aikido_types.CloudConfigData, error) {
	cloudConfig := &aikido_types.CloudConfigData{}
	err := json.Unmarshal(resp, &cloudConfig)
	if err != nil {
		return nil, ErrParsingConfig
	}

	return cloudConfig, nil
}

// FetchListsConfig fetches firewall blocklists to keep local security rules synchronized with cloud configuration.
func (c *Client) FetchListsConfig() (*aikido_types.ListsConfigData, error) {
	response, err := c.sendCloudRequest(c.apiEndpoint, listsAPIRoute, listsAPIMethod, nil)
	if err != nil {
		logCloudRequestError("Error in sending lists request: ", err)
		return nil, err
	}

	listsConfig := aikido_types.ListsConfigData{}
	err = json.Unmarshal(response, &listsConfig)
	if err != nil {
		log.Warn("Failed to unmarshal lists config!")
		return nil, err
	}

	return &listsConfig, err
}
