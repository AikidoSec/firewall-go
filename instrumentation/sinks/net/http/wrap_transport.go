package http

import (
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"

	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/zen"
)

// ssrfTransport wraps an *http.Transport to check DNS-resolved IPs for SSRF.
// RoundTrip propagates the request context (including GLS) into the Go context
// so that DialContext (which runs in a different goroutine) can access user input.
// DialContext resolves DNS, checks for private IPs, and connects to the resolved
// IP directly to prevent TOCTOU / DNS rebinding attacks.
type ssrfTransport struct {
	inner *http.Transport
}

func (t *ssrfTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Propagate request context from GLS into the Go context so that
	// DialContext (running in a transport goroutine) can access it.
	ctx := request.EnsureContextPropagated(req.Context())
	if ctx != req.Context() {
		req = req.WithContext(ctx)
	}

	resp, err := t.inner.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	// Track redirects for SSRF detection: if this response redirects,
	// record the source -> destination so that DialContext can trace a
	// redirect chain back to user input.
	if isRedirect(resp.StatusCode) {
		if loc := resp.Header.Get("Location"); loc != "" {
			recordRedirect(req.URL, loc, request.GetContext(ctx))
		}
	}

	return resp, nil
}

func isRedirect(statusCode int) bool {
	return statusCode >= 300 && statusCode < 400
}

func recordRedirect(source *url.URL, location string, reqCtx *request.Context) {
	if reqCtx == nil || source == nil {
		return
	}

	dest, err := url.Parse(location)
	if err != nil {
		return
	}
	// Resolve relative redirects against the source URL
	dest = source.ResolveReference(dest)

	reqCtx.AddOutgoingRedirect(request.RedirectEntry{
		SourceHostname: source.Hostname(),
		SourcePort:     portFromURL(source),
		DestHostname:   dest.Hostname(),
		DestPort:       portFromURL(dest),
	})
}

func portFromURL(u *url.URL) uint32 {
	if p := u.Port(); p != "" {
		if n, err := strconv.ParseUint(p, 10, 32); err == nil {
			return uint32(n)
		}
	}
	switch u.Scheme {
	case "https":
		return 443
	default:
		return 80
	}
}

var wrappedTransports sync.Map // map[*http.Transport]*ssrfTransport

// WrapTransport wraps an http.RoundTripper with SSRF DNS resolution checking.
// Only *http.Transport is wrapped (DialContext is needed); other RoundTrippers
// are returned as-is. Wrapped transports are cached per original transport pointer.
func WrapTransport(rt http.RoundTripper) http.RoundTripper {
	if !zen.ShouldProtect() {
		return rt
	}

	// Don't double wrap
	if _, ok := rt.(*ssrfTransport); ok {
		return rt
	}

	t, ok := rt.(*http.Transport)
	if !ok {
		return rt
	}

	if cached, ok := wrappedTransports.Load(t); ok {
		return cached.(*ssrfTransport)
	}

	clone := t.Clone()
	originalDialContext := clone.DialContext
	if originalDialContext == nil {
		var d net.Dialer
		originalDialContext = d.DialContext
	}
	clone.DialContext = ssrfDialContext(originalDialContext)

	wrapped := &ssrfTransport{inner: clone}
	wrappedTransports.Store(t, wrapped)
	return wrapped
}
