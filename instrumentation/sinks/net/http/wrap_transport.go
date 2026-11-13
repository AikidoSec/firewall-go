package http

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"

	"github.com/AikidoSec/firewall-go/internal/normalize"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/zen"
)

// ssrfTransport wraps any http.RoundTripper for context propagation and redirect
// tracking. DNS protection is injected separately for *http.Transport in WrapTransport.
// RoundTrip propagates the request context (including GLS) into the Go context
// so that DialContext (which runs in a different goroutine) can access user input.
type ssrfTransport struct {
	inner http.RoundTripper
}

func (t *ssrfTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Propagate request context from GLS into the Go context so that
	// DialContext (running in a transport goroutine) can access it.
	ctx := request.EnsureContextPropagated(req.Context())
	if ctx != req.Context() {
		req = req.WithContext(ctx)
	}

	resp, err := t.inner.RoundTrip(req)
	if err != nil || resp == nil {
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

func (t *ssrfTransport) CloseIdleConnections() {
	if inner, ok := t.inner.(interface{ CloseIdleConnections() }); ok {
		inner.CloseIdleConnections()
	}
}

func isRedirect(statusCode int) bool {
	// Match net/http's redirectBehavior: other 3xx responses are not followed,
	// even when they include a Location header.
	switch statusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
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
		SourceHostname: normalize.Hostname(source.Hostname()),
		SourcePort:     portFromURL(source),
		DestHostname:   normalize.Hostname(dest.Hostname()),
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

var (
	wrappedTransports sync.Map   // map[*http.Transport]*ssrfTransport
	wrapMu            sync.Mutex // guards first-time DialContext injection per transport
)

// WrapTransport wraps an http.RoundTripper for context propagation and redirect
// tracking. Only directly accessible *http.Transports receive DNS-level SSRF
// protection, since custom RoundTrippers do not expose their dialers.
// Standard transport wrappers are cached per original transport pointer.
//
// Rather than cloning the transport (which can interfere with HTTP/2 connection
// state), we inject the SSRF DialContext directly onto the original transport.
// This preserves the transport's existing h2 configuration.
func WrapTransport(rt http.RoundTripper) http.RoundTripper {
	if rt == nil || !zen.ShouldProtect() {
		return rt
	}

	// Don't double wrap
	if _, ok := rt.(*ssrfTransport); ok {
		return rt
	}

	t, ok := rt.(*http.Transport)
	if !ok {
		// Custom transports can be non-comparable, so do not use them as cache keys.
		return &ssrfTransport{inner: rt}
	}

	// Mutex prevents two goroutines from both reading t.DialContext before
	// either has written the SSRF wrapper back, which would cause double-wrapping.
	wrapMu.Lock()
	defer wrapMu.Unlock()

	if cached, ok := wrappedTransports.Load(t); ok {
		return cached.(*ssrfTransport)
	}

	originalDialContext := t.DialContext
	hadCustomDialContext := originalDialContext != nil
	if originalDialContext == nil {
		// Injecting DialContext makes Transport.dial stop consulting Dial, so keep using it here.
		if userDial := t.Dial; userDial != nil { //nolint:staticcheck // intentionally preserving deprecated field
			originalDialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
				return userDial(network, addr)
			}
		} else {
			var d net.Dialer
			originalDialContext = d.DialContext
		}
	}
	t.DialContext = ssrfDialContext(originalDialContext)

	// DialTLSContext and the deprecated DialTLS bypass DialContext for non-proxied HTTPS, so they need the same wrapper.
	switch {
	case t.DialTLSContext != nil:
		t.DialTLSContext = ssrfDialContext(t.DialTLSContext)
	case t.DialTLS != nil: //nolint:staticcheck // intentionally preserving deprecated field
		// Go prefers DialTLSContext, so installing there hands us the request context.
		userDialTLS := t.DialTLS //nolint:staticcheck // intentionally preserving deprecated field
		t.DialTLSContext = ssrfDialContext(func(_ context.Context, network, addr string) (net.Conn, error) {
			return userDialTLS(network, addr)
		})
	}

	// Go disables h2 auto-upgrade when any of Dial, DialTLS, DialContext, or
	// TLSClientConfig is set and ForceAttemptHTTP2 is false. We've just injected
	// a DialContext, so if none of those other fields were set beforehand, we're
	// the sole reason h2 would now be disabled, so restore the default behavior.
	if !hadCustomDialContext &&
		!t.ForceAttemptHTTP2 &&
		t.TLSClientConfig == nil &&
		t.Dial == nil && //nolint:staticcheck // intentionally checking deprecated field to preserve user intent
		t.DialTLS == nil { //nolint:staticcheck // intentionally checking deprecated field to preserve user intent
		t.ForceAttemptHTTP2 = true
	}

	wrapped := &ssrfTransport{inner: t}
	wrappedTransports.Store(t, wrapped)
	return wrapped
}
