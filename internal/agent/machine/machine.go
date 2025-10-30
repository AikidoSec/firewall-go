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
	HostName   string
	DomainName string
	OS         string
	OSVersion  string
	IPAddress  string
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

func getDomainName(ctx context.Context) string {
	// We're using `hostname -f` instead of `hostname --domain` for darwin support
	cmd := exec.CommandContext(ctx, "hostname", "-f")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	fqdn := strings.TrimSpace(string(output))

	// Extract domain by removing the first part (hostname)
	// Example: if fqdn is "web01.prod.example.com", we split into ["web01", "prod.example.com"]
	// and return parts[1] which is "prod.example.com"
	parts := strings.SplitN(fqdn, ".", 2)
	if len(parts) == 2 {
		return parts[1]
	}

	return ""
}

func getOSVersion(ctx context.Context) string {
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

func getMachineData(ctx context.Context) MachineData {
	return MachineData{
		HostName:   getHostName(),
		DomainName: getDomainName(ctx),
		OS:         runtime.GOOS,
		OSVersion:  getOSVersion(ctx),
		IPAddress:  getIPAddress(),
	}
}

func Init() {
	initOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		Machine = getMachineData(ctx)
		log.Debug("Machine data", slog.Any("machine", Machine))
	})
}
