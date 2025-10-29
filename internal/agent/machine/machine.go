package machine

import (
	"log/slog"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/log"
)

// Machine holds data about the current machine, computed at init
var Machine aikido_types.MachineData

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

func getMachineData() aikido_types.MachineData {
	return aikido_types.MachineData{
		HostName:   getHostName(),
		DomainName: getDomainName(),
		OS:         runtime.GOOS,
		OSVersion:  getOSVersion(),
		IPAddress:  getIPAddress(),
	}
}

func Init() {
	Machine = getMachineData()

	log.Info("Machine info", slog.Any("machine", Machine))
}
