package zen

// This is the main module users will interact with : SetUser, ShouldBlockRequest, middleware, ...

import (
	"encoding/json"
	"os"
	"runtime"

	"github.com/AikidoSec/firewall-go/internal/config"
	"github.com/AikidoSec/firewall-go/internal/grpc"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/zen-internals-agent/aikido_types"
	"github.com/AikidoSec/zen-internals-agent/zen_go_bindings"
)

type combined struct {
	aikido_types.EnvironmentConfigData
	aikido_types.AikidoConfigData
}

// Init needs to be called in the user's app to start the background process
func Init() error {
	// Logger :
	config.AikidoConfig.LogLevel = "DEBUG"
	log.Init()
	log.SetLogLevel(config.AikidoConfig.LogLevel)

	socket, err := os.CreateTemp("", "aikido-test.sock")
	if err != nil {
		return err
	}

	// gRPC Config :
	config.AikidoConfig.Token = os.Getenv("AIKIDO_TOKEN")
	config.EnvironmentConfig.SocketPath = socket.Name()
	config.EnvironmentConfig.CollectApiSchema = true

	err = initGRPCServer() // gRPC Server
	if err != nil {
		return err
	}

	grpc.Init() // gRPC Client

	return nil
}

func initGRPCServer() error {
	// gRPC Server :
	environmentConfig := aikido_types.EnvironmentConfigData{
		PlatformName:    "golang",
		PlatformVersion: runtime.Version(),
		Library:         "firewall-go",
		Endpoint:        "https://guard.aikido.dev/",
		ConfigEndpoint:  "https://runtime.aikido.dev/",
		SocketPath:      config.EnvironmentConfig.SocketPath,
		Version:         config.Version, // firewall-go version
	}
	aikidoConfig := aikido_types.AikidoConfigData{
		LogLevel:         config.AikidoConfig.LogLevel,
		Token:            config.AikidoConfig.Token,
		CollectApiSchema: config.EnvironmentConfig.CollectApiSchema,
	}
	jsonBytes, err := json.Marshal(combined{environmentConfig, aikidoConfig})
	if err != nil {
		return err
	}

	go zen_go_bindings.AgentInit(string(jsonBytes))
	return nil
}
