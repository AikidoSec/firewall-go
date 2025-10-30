package machine

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/AikidoSec/firewall-go/internal/log"
)

type MachineData struct {
	HostName  string
	OS        string
	OSVersion string
	IPAddress string
}

// Machine caches immutable system information to avoid expensive repeated system calls.
var (
	Machine  MachineData
	initOnce sync.Once
)

func getHostName() string {
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}
	return hostname
}

func getOSVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "uname", "-r")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func getIPAddress() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				return ipNet.IP.String()
			}
		}
	}
	return ""
}

func getMachineData() MachineData {
	return MachineData{
		HostName:  getHostName(),
		OS:        runtime.GOOS,
		OSVersion: getOSVersion(),
		IPAddress: getIPAddress(),
	}
}

func Init() {
	initOnce.Do(func() {
		Machine = getMachineData()
		log.Debug("Machine data", slog.Any("machine", Machine))
	})
}
