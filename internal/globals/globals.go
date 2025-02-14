package globals

import (
	"github.com/AikidoSec/firewall-go/internal/types"
	"sync"
)

var EnvironmentConfig types.EnvironmentConfigData

var AikidoConfig types.AikidoConfigData

var CloudConfig types.CloudConfigData
var CloudConfigMutex sync.Mutex

const (
	Version = "1.0.0"
)
