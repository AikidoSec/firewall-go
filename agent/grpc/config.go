package grpc

import (
	"github.com/AikidoSec/firewall-go/agent/globals"
	"github.com/AikidoSec/firewall-go/agent/log"
)

func storeConfig(token, logLevel string, blocking, localhostAllowedByDefault, collectApiSchema bool) {
	globals.AikidoConfig.ConfigMutex.Lock()
	defer globals.AikidoConfig.ConfigMutex.Unlock()

	globals.AikidoConfig.Token = token
	globals.AikidoConfig.LogLevel = logLevel
	globals.AikidoConfig.Blocking = blocking
	globals.AikidoConfig.LocalhostAllowedByDefault = localhostAllowedByDefault
	globals.AikidoConfig.CollectApiSchema = collectApiSchema

	log.SetLogLevel(globals.AikidoConfig.LogLevel)
	log.Debugf("Updated Aikido Config with the one passed via gRPC!")
}
