package cloud

import (
	. "github.com/AikidoSec/zen-internals-agent/aikido_types"
	"github.com/AikidoSec/zen-internals-agent/globals"
	"github.com/AikidoSec/zen-internals-agent/utils"
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
