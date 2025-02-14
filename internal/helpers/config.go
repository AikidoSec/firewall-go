package helpers

import "github.com/AikidoSec/firewall-go/internal/globals"

func GetCloudConfigUpdatedAt() int64 {
	globals.CloudConfigMutex.Lock()
	defer globals.CloudConfigMutex.Unlock()

	return globals.CloudConfig.ConfigUpdatedAt
}
