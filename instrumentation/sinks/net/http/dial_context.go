package http

import (
	"context"
	"errors"
	"net"
	"strconv"

	"github.com/AikidoSec/firewall-go/internal/vulnerabilities"
	"github.com/AikidoSec/firewall-go/internal/vulnerabilities/ssrf"
	"github.com/AikidoSec/firewall-go/zen"
)

// ssrfDialContext wraps a DialContext function to check the connected IP for SSRF.
// It lets the original dialer handle DNS resolution and connection (preserving
// Happy Eyeballs, multi-IP fallback, etc.), then inspects the resulting
// connection's remote address. If it's a private IP and the hostname originates
// from user input, the connection is closed and an error is returned before any
// HTTP data is sent.
func ssrfDialContext(original func(ctx context.Context, network, addr string) (net.Conn, error)) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, dialErr := original(ctx, network, addr)
		if dialErr != nil {
			return conn, dialErr
		}

		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return conn, nil
		}

		remoteIP, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			return conn, nil
		}

		portNum, _ := strconv.ParseUint(port, 10, 32)

		if err := scanSSRF(ctx, host, uint32(portNum), []string{remoteIP}); err != nil {
			_ = conn.Close()
			return nil, err
		}

		return conn, nil
	}
}

// scanSSRF runs the SSRF vulnerability scan with the given hostname and resolved IPs.
// The hostname is used for user-input matching; the resolved IPs are checked for
// private addresses inside the scan function.
func scanSSRF(ctx context.Context, hostname string, port uint32, resolvedIPs []string) error {
	scanErr := vulnerabilities.Scan(ctx, "net/http.Client.Do",
		ssrf.SSRFVulnerability, &ssrf.ScanArgs{
			Hostname:    hostname,
			Port:        port,
			ResolvedIPs: resolvedIPs,
		})
	if scanErr != nil {
		attackKind := vulnerabilities.KindSSRF
		var attackErr *vulnerabilities.AttackDetectedError
		if errors.As(scanErr, &attackErr) {
			attackKind = attackErr.Kind
		}
		return errors.Join(zen.ErrAttackBlocked(attackKind), scanErr)
	}
	return nil
}
