package helpers

import "github.com/AikidoSec/firewall-go/internal/globals"

func GetBlockingMode() int {
	globals.CloudConfigMutex.Lock()
	defer globals.CloudConfigMutex.Unlock()
	return globals.CloudConfig.Block
}
func IsBlockingEnabled() bool {
	return GetBlockingMode() == 1
}
