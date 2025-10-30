package machine

import (
	"context"
	"net"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetMachineData(t *testing.T) {
	machineData := getMachineData(context.TODO())

	assert.Equal(t, runtime.GOOS, machineData.OS, "OS should match runtime.GOOS")
	assert.NotEmpty(t, machineData.OSVersion, "OSVersion should be set")
	assert.NotEmpty(t, machineData.HostName, "HostName should be set")
	assert.NotEmpty(t, machineData.DomainName, "DomainName should be set")
	assert.NotEmpty(t, machineData.OSVersion, "OSVersion should be set")
	assert.NotEmpty(t, machineData.IPAddress, "IPAddress should be set")

	parsedIP := net.ParseIP(machineData.IPAddress)
	assert.NotNil(t, parsedIP, "IPAddress should be a valid IP address")
	assert.False(t, parsedIP.IsLoopback(), "IPAddress should not be loopback")
}
