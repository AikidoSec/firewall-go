package config

import (
	"sync"
)

var CloudConfig CloudConfigData
var CloudConfigMutex sync.RWMutex

const (
	Version = "1.0.0"
)
