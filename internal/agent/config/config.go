package config

import (
	"fmt"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/globals"
	"github.com/AikidoSec/firewall-go/internal/agent/log"
)

func Init(environmentConfig *aikido_types.EnvironmentConfigData, aikidoConfig *aikido_types.AikidoConfigData) bool {
	globals.EnvironmentConfig = environmentConfig
	globals.AikidoConfig = aikidoConfig

	if globals.AikidoConfig.LogLevel != "" {
		if err := log.SetLogLevel(globals.AikidoConfig.LogLevel); err != nil {
			panic(fmt.Sprintf("Error setting log level: %s", err))
		}
	}

	log.Infof("Loaded local config: %+v", globals.EnvironmentConfig)

	if globals.AikidoConfig.Token == "" {
		log.Infof("No token set!")
	}

	return true
}

func Uninit() {}

func GetToken() string {
	globals.AikidoConfig.ConfigMutex.Lock()
	defer globals.AikidoConfig.ConfigMutex.Unlock()

	return globals.AikidoConfig.Token
}

func IsBlockingEnabled() bool {
	serviceConfigMutex.RLock()
	defer serviceConfigMutex.RUnlock()

	return serviceConfig.Block
}
