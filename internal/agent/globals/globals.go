package globals

import (
	"sync"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
)

// Local config that contains info about socket path, platform, library version...
var EnvironmentConfig *aikido_types.EnvironmentConfigData

// Aikido config that contains info about endpoint, log_level, token, ...
var AikidoConfig *aikido_types.AikidoConfigData

// Global stats data, including mutex used to sync access to stats data across the go routines
var StatsData aikido_types.StatsDataType

// Users map, which holds the current users and their data
var Users = make(map[string]aikido_types.User)

// Users mutex used to sync access across the go routines
var UsersMutex sync.Mutex

// MiddlewareInstalled boolean value to be reported on heartbeat events
var MiddlewareInstalled uint32
