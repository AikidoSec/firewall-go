package config

import (
	"sync"
)

var CloudConfig CloudConfigData
var CloudConfigMutex sync.Mutex

const (
	Version = "1.0.0"
)
