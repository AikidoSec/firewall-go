package cloud

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/log"
)

const resolveTimeout = 5 * time.Second

// ResolveRealtimeURL probes the given endpoint and returns the resolved URL and
// whether SSE is supported. If AIKIDO_REALTIME_ENDPOINT is set the endpoint is
// used as-is. Otherwise zen.aikido.dev is probed; on failure it falls back to
// runtime.aikido.dev with polling only (no SSE).
func ResolveRealtimeURL(endpoint, token string) (string, bool) {
	if os.Getenv("AIKIDO_REALTIME_ENDPOINT") != "" {
		return endpoint, true
	}

	if os.Getenv("AIKIDO_REALTIME_ENABLED") != "true" {
		return config.FallbackRealtimeEndpoint, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()

	probeURL, err := url.JoinPath(endpoint, "config")
	if err != nil {
		return endpoint, true
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return endpoint, true
	}
	req.Header.Set("Authorization", token)

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		u, _ := url.Parse(endpoint)
		log.Info("Unable to reach realtime endpoint, falling back. SSE will not be available.",
			slog.String("endpoint", u.Host),
			slog.String("fallback", config.FallbackRealtimeEndpoint))
		return config.FallbackRealtimeEndpoint, false
	}
	_ = resp.Body.Close()

	return endpoint, true
}
