package zen

// This is the main module users will interact with : SetUser, ShouldBlockRequest, middleware, ...

import (
	"encoding/json"
	"github.com/AikidoSec/firewall-go/internal/globals"
	"github.com/AikidoSec/zen-internals-agent/aikido_types"
	"github.com/AikidoSec/zen-internals-agent/zen_go_bindings"
	"os"
	"runtime"
)

type combined struct {
	aikido_types.EnvironmentConfigData
	aikido_types.AikidoConfigData
}

// Init needs to be called in the user's app to start the background process
func Init() {
	globals.AikidoConfig.LogLevel = "DEBUG"
	globals.AikidoConfig.Token = os.Getenv("AIKIDO_TOKEN")
	globals.EnvironmentConfig.SocketPath = "/var/home/primary/firewall-go/socks/aikido-test.sock"
	environmentConfig := aikido_types.EnvironmentConfigData{
		PlatformName:    "golang",
		PlatformVersion: runtime.Version(),
		Library:         "firewall-go",
		Endpoint:        "https://guard.aikido.dev/",
		ConfigEndpoint:  "https://runtime.aikido.dev/",
		SocketPath:      globals.EnvironmentConfig.SocketPath,
		Version:         globals.Version, // firewall-go version
	}
	aikidoConfig := aikido_types.AikidoConfigData{
		LogLevel: globals.AikidoConfig.LogLevel,
		Token:    globals.AikidoConfig.Token,
	}
	jsonBytes, err := json.Marshal(combined{environmentConfig, aikidoConfig})
	if err != nil {
		panic(err)
	}

	go zen_go_bindings.AgentInit(string(jsonBytes))
}
