package http

import (
	"context"
	"errors"
	"net"
	"slices"
	"strconv"

	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/vulnerabilities"
	"github.com/AikidoSec/firewall-go/vulnerabilities/ssrf"
	"github.com/AikidoSec/firewall-go/zen"
)

// ssrfDialContext wraps a DialContext function to check the connected IP for SSRF.
// It lets the original dialer handle DNS resolution and connection (preserving
// Happy Eyeballs, multi-IP fallback, etc.), then inspects the resulting
// connection's remote address. If it's a private IP and the hostname originates
// from user input, the connection is closed and an error is returned before any
// HTTP data is sent.
func ssrfDialContext(originalDialContext func(ctx context.Context, network, addr string) (net.Conn, error)) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, dialErr := originalDialContext(ctx, network, addr)
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
// If no direct match is found, it walks the redirect chain to find the origin
// hostname and checks that against user input instead.
func scanSSRF(ctx context.Context, hostname string, port uint32, resolvedIPs []string) error {
	scanErr := vulnerabilities.Scan(ctx, "net/http.Client.Do",
		ssrf.SSRFVulnerability, &ssrf.ScanArgs{
			Hostname:    hostname,
			Port:        port,
			ResolvedIPs: resolvedIPs,
		})
	if scanErr != nil {
		return wrapSSRFError(scanErr)
	}

	reqCtx := request.GetContext(ctx)
	if reqCtx == nil {
		return nil
	}

	originHostname, originPort, found := findRedirectOrigin(reqCtx.GetOutgoingRedirects(), hostname, port)
	if !found {
		return nil
	}

	scanErr = vulnerabilities.Scan(ctx, "net/http.Client.Do",
		ssrf.SSRFVulnerability, &ssrf.ScanArgs{
			Hostname:    originHostname,
			Port:        originPort,
			ResolvedIPs: resolvedIPs,
		})
	if scanErr != nil {
		return wrapSSRFError(scanErr)
	}

	return nil
}

const maxRedirectChainDepth = 100

// findRedirectOrigin walks the redirect chain backwards from hostname:port and
// returns the origin - the furthest-back source that ultimately led here.
// Returns false if hostname:port is not the destination of any recorded redirect.
func findRedirectOrigin(redirects []request.RedirectEntry, hostname string, port uint32) (string, uint32, bool) {
	visited := map[request.RedirectEntry]bool{{DestHostname: hostname, DestPort: port}: true}
	current := request.RedirectEntry{DestHostname: hostname, DestPort: port}

	for range maxRedirectChainDepth {
		idx := slices.IndexFunc(redirects, func(r request.RedirectEntry) bool {
			return r.DestHostname == current.DestHostname &&
				(r.DestPort == current.DestPort || r.DestPort == 0 || current.DestPort == 0)
		})
		if idx == -1 {
			break
		}
		next := redirects[idx]
		step := request.RedirectEntry{DestHostname: next.SourceHostname, DestPort: next.SourcePort}
		if visited[step] {
			break
		}
		visited[step] = true
		current = step
	}

	if current.DestHostname == hostname && current.DestPort == port {
		return "", 0, false
	}
	return current.DestHostname, current.DestPort, true
}

func wrapSSRFError(scanErr error) error {
	attackKind := vulnerabilities.KindSSRF
	var attackErr *vulnerabilities.AttackDetectedError
	if errors.As(scanErr, &attackErr) {
		attackKind = attackErr.Kind
	}
	return errors.Join(zen.ErrAttackBlocked(attackKind), scanErr)
}
