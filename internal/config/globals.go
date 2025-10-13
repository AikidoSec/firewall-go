package config

import (
	"sync"
)

var ServiceConfig ServiceConfigData
var ServiceConfigMutex sync.RWMutex

const (
	Version = "1.0.0"
)
