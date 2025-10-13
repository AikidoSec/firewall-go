package globals

import (
	"sync"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
)

// Local config that contains info about socket path, platform, library version...
var EnvironmentConfig aikido_types.EnvironmentConfigData

// Aikido config that contains info about endpoint, log_level, token, ...
var AikidoConfig aikido_types.AikidoConfigData

// Cloud config that is obtain as a result from sending events to cloud or pulling the config when it changes
var CloudConfig aikido_types.CloudConfigData

// Config mutex used to sync access to configuration data across the multiple go routines that we run in parallel
var CloudConfigMutex sync.Mutex

// Data about the current machine, computed at init
var Machine aikido_types.MachineData

// List of outgoing hostnames, their ports and number of hits, collected from the requests
var Hostnames = make(map[string]map[uint32]uint64)

// Hostnames mutex used to sync access to hostnames data across the go routines
var HostnamesMutex sync.Mutex

// List of routes and their methods and count of calls collect from the requests
// [method][route] = hits
var Routes = make(map[string]map[string]*aikido_types.Route)

// Routes mutex used to sync access to routes data across the go routines
var RoutesMutex sync.Mutex

// Global stats data, including mutex used to sync access to stats data across the go routines
var StatsData aikido_types.StatsDataType

// Users map, which holds the current users and their data
var Users = make(map[string]aikido_types.User)

// Users mutex used to sync access across the go routines
var UsersMutex sync.Mutex

// MiddlewareInstalled boolean value to be reported on heartbeat events
var MiddlewareInstalled uint32

// Got some request info passed via gRPC to the Agent
var GotTraffic uint32

// Did we log a token error?
var LoggedTokenError uint32

// Users map, which holds the current users and their data
var AttackDetectedEventsSentAt []int64

// Users mutex used to sync access across the go routines
var AttackDetectedEventsSentAtMutex sync.Mutex
