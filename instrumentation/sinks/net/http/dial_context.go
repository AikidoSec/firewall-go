package http

import (
	"context"
	"errors"
	"net"
	"slices"
	"strconv"

	"github.com/AikidoSec/firewall-go/internal/normalize"
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
		host = normalize.Hostname(host)

		remoteIP, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			return conn, nil
		}

		portNum, _ := strconv.ParseUint(port, 10, 32)

		if err := checkStoredSSRF(ctx, host, []string{remoteIP}); err != nil {
			_ = conn.Close()
			return nil, err
		}

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
// If no direct match is found, it checks every ancestor hostname in the redirect
// chain against user input instead.
func scanSSRF(ctx context.Context, hostname string, port uint32, resolvedIPs []string) error {
	scanOpts := vulnerabilities.ScanOptions{Module: "net/http"}
	scanErr := vulnerabilities.ScanWithOptions(ctx, "net/http.Client.Do",
		ssrf.SSRFVulnerability, &ssrf.ScanArgs{
			Hostname:    hostname,
			Port:        port,
			ResolvedIPs: resolvedIPs,
		}, scanOpts)
	if scanErr != nil {
		return wrapSSRFError(scanErr)
	}

	reqCtx := request.GetContext(ctx)
	if reqCtx == nil {
		return nil
	}

	for _, ancestor := range findRedirectAncestors(reqCtx.GetOutgoingRedirects(), hostname, port) {
		scanErr = vulnerabilities.ScanWithOptions(ctx, "net/http.Client.Do",
			ssrf.SSRFVulnerability, &ssrf.ScanArgs{
				Hostname:    ancestor.DestHostname,
				Port:        ancestor.DestPort,
				ResolvedIPs: resolvedIPs,
			}, scanOpts)
		if scanErr != nil {
			return wrapSSRFError(scanErr)
		}
	}

	return nil
}

const maxRedirectChainDepth = 100

// findRedirectAncestors walks the redirect chain backwards from hostname:port
// and returns every ancestor encountered along the way. outgoingRedirects is
// shared across every outbound call in the request, so a cycle can combine
// entries from unrelated calls; the node where the walk stops isn't
// necessarily the real origin, so every ancestor visited is returned instead
// of just the last one.
func findRedirectAncestors(redirects []request.RedirectEntry, hostname string, port uint32) []request.RedirectEntry {
	start := request.RedirectEntry{DestHostname: hostname, DestPort: port}
	visited := map[request.RedirectEntry]bool{start: true}
	current := start

	var ancestors []request.RedirectEntry
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
		if step != start {
			ancestors = append(ancestors, step)
		}
		if visited[step] {
			break
		}
		visited[step] = true
		current = step
	}

	return ancestors
}

func wrapSSRFError(scanErr error) error {
	attackKind := vulnerabilities.KindSSRF
	var attackErr *vulnerabilities.AttackDetectedError
	if errors.As(scanErr, &attackErr) {
		attackKind = attackErr.Kind
	}
	return errors.Join(zen.ErrAttackBlocked(attackKind), scanErr)
}

func checkStoredSSRF(ctx context.Context, hostname string, resolvedIPs []string) error {
	if request.IsBypassed(ctx) {
		return nil
	}

	result := ssrf.CheckStoredSSRF(hostname, resolvedIPs)
	if result == nil {
		return nil
	}

	scanErr := vulnerabilities.OnStoredSSRF(ctx, "net/http", "net/http.Client.Do", result.Hostname, result.PrivateIP)
	if scanErr != nil {
		return errors.Join(zen.ErrAttackBlocked(vulnerabilities.KindStoredSSRF), scanErr)
	}
	return nil
}
