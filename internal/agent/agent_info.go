package agent

import (
	"github.com/AikidoSec/firewall-go/internal/agent/cloud"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/AikidoSec/firewall-go/internal/agent/machine"
)

func getAgentInfo() cloud.AgentInfo {
	return cloud.AgentInfo{
		DryMode:   !config.IsBlockingEnabled(),
		Hostname:  machine.Machine.HostName,
		Version:   globals.EnvironmentConfig.Version,
		IPAddress: machine.Machine.IPAddress,
		OS: cloud.OSInfo{
			Name:    machine.Machine.OS,
			Version: machine.Machine.OSVersion,
		},
		Platform: cloud.PlatformInfo{
			Name:    globals.EnvironmentConfig.PlatformName,
			Version: globals.EnvironmentConfig.PlatformVersion,
		},
		Packages: make(map[string]string, 0),
		NodeEnv:  "",
		Library:  globals.EnvironmentConfig.Library,
	}
}
