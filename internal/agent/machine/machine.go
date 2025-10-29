package machine

import (
	"log/slog"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"github.com/AikidoSec/firewall-go/internal/log"
)

type MachineData struct {
	HostName   string
	DomainName string
	OS         string
	OSVersion  string
	IPAddress  string
}

// Machine holds data about the current machine, computed at init
var Machine MachineData
var initOnce sync.Once

func getHostName() string {
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}
	return hostname
}

func getDomainName() string {
	cmd := exec.Command("hostname", "-f")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	fqdn := strings.TrimSpace(string(output))

	// Extract domain by removing the first part (hostname)
	parts := strings.SplitN(fqdn, ".", 2)
	if len(parts) == 2 {
		return parts[1]
	}

	return ""
}

func getOSVersion() string {
	cmd := exec.Command("uname", "-r")
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
		HostName:   getHostName(),
		DomainName: getDomainName(),
		OS:         runtime.GOOS,
		OSVersion:  getOSVersion(),
		IPAddress:  getIPAddress(),
	}
}

func Init() {
	initOnce.Do(func() {
		Machine = getMachineData()
		log.Debug("Machine data", slog.Any("machine", Machine))
	})
}
