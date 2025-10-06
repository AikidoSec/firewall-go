package cloud

import (
	. "github.com/AikidoSec/firewall-go/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/agent/globals"
	"github.com/AikidoSec/firewall-go/agent/utils"
)

func SendStartEvent() {
	startedEvent := Started{
		Type:  "started",
		Agent: GetAgentInfo(),
		Time:  utils.GetTime(),
	}

	response, err := SendCloudRequest(globals.EnvironmentConfig.Endpoint, globals.EventsAPI, globals.EventsAPIMethod, startedEvent)
	if err != nil {
		LogCloudRequestError("Error in sending start event: ", err)
		return
	}
	StoreCloudConfig(response)
}
