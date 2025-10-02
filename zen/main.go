package zen

// This is the main module users will interact with : SetUser, ShouldBlockRequest, middleware, ...

import (
	"encoding/json"
	"github.com/AikidoSec/firewall-go/internal/globals"
	"github.com/AikidoSec/firewall-go/internal/grpc"
	"github.com/AikidoSec/firewall-go/internal/log"
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
	// Logger :
	globals.AikidoConfig.LogLevel = "DEBUG"
	log.Init()
	log.SetLogLevel(globals.AikidoConfig.LogLevel)

	// gRPC Config :
	globals.AikidoConfig.Token = os.Getenv("AIKIDO_TOKEN")
	globals.EnvironmentConfig.SocketPath = "/var/home/primary/firewall-go/socks/aikido-test.sock"
	globals.EnvironmentConfig.CollectApiSchema = true
	initGRPCServer() // gRPC Server
	grpc.Init()      // gRPC Client
}

func initGRPCServer() {
	// gRPC Server :
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
		LogLevel:         globals.AikidoConfig.LogLevel,
		Token:            globals.AikidoConfig.Token,
		CollectApiSchema: globals.EnvironmentConfig.CollectApiSchema,
	}
	jsonBytes, err := json.Marshal(combined{environmentConfig, aikidoConfig})
	if err != nil {
		panic(err)
	}
	go zen_go_bindings.AgentInit(string(jsonBytes))
}
