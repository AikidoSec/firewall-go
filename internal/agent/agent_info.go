package agent

import (
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/AikidoSec/firewall-go/internal/agent/machine"
)

func getAgentInfo() aikido_types.AgentInfo {
	return aikido_types.AgentInfo{
		DryMode:   !config.IsBlockingEnabled(),
		Hostname:  machine.Machine.HostName,
		Version:   globals.EnvironmentConfig.Version,
		IPAddress: machine.Machine.IPAddress,
		OS: aikido_types.OsInfo{
			Name:    machine.Machine.OS,
			Version: machine.Machine.OSVersion,
		},
		Platform: aikido_types.PlatformInfo{
			Name:    globals.EnvironmentConfig.PlatformName,
			Version: globals.EnvironmentConfig.PlatformVersion,
		},
		Packages: make(map[string]string, 0),
		NodeEnv:  "",
		Library:  globals.EnvironmentConfig.Library,
	}
}
