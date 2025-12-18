package globals

import (
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
)

// Local config that contains info about socket path, platform, library version...
var EnvironmentConfig *aikido_types.EnvironmentConfigData

// Aikido config that contains info about endpoint, log_level, token, ...
var AikidoConfig *aikido_types.AikidoConfigData
