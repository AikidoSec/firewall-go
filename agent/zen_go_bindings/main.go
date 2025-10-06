package zen_go_bindings

import (
	"github.com/AikidoSec/zen-internals-agent/cloud"
	"github.com/AikidoSec/zen-internals-agent/config"
	"github.com/AikidoSec/zen-internals-agent/globals"
	"github.com/AikidoSec/zen-internals-agent/grpc"
	"github.com/AikidoSec/zen-internals-agent/log"
	"github.com/AikidoSec/zen-internals-agent/machine"
	"github.com/AikidoSec/zen-internals-agent/rate_limiting"
)

func AgentInit(initJson string) (initOk bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Warn("Recovered from panic:", r)
			initOk = false
		}
	}()

	log.Init()
	machine.Init()
	if !config.Init(initJson) || !grpc.Init() {
		return false
	}

	cloud.Init()
	rate_limiting.Init()

	log.Infof("Aikido Agent v%s loaded!", globals.EnvironmentConfig.Version)
	return true
}

func AgentUninit() {
	rate_limiting.Uninit()
	cloud.Uninit()
	grpc.Uninit()
	config.Uninit()

	log.Infof("Aikido Agent v%s unloaded!", globals.EnvironmentConfig.Version)
	log.Uninit()
}
