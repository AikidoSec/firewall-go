package zen_go_bindings

import (
	"github.com/AikidoSec/firewall-go/agent/cloud"
	"github.com/AikidoSec/firewall-go/agent/config"
	"github.com/AikidoSec/firewall-go/agent/globals"
	"github.com/AikidoSec/firewall-go/agent/grpc"
	"github.com/AikidoSec/firewall-go/agent/log"
	"github.com/AikidoSec/firewall-go/agent/machine"
	"github.com/AikidoSec/firewall-go/agent/rate_limiting"
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
