package zen

import (
	"context"
	"errors"
	"sync"

	"github.com/AikidoSec/firewall-go/internal/agent"
	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/request"
)

var ErrEventNameEmpty = errors.New("event name cannot be empty")

var trackOutsideRequestWarnOnce sync.Once

type trackOptions struct {
	metadata map[string]string
}

type TrackOption func(*trackOptions)

// WithMetadata attaches additional metadata to a tracked event.
//
// Not yet used.
func WithMetadata(metadata map[string]string) TrackOption {
	return func(o *trackOptions) {
		o.metadata = metadata
	}
}

// Track records something happening in the application, like a failed
// login, signup, or password reset, so Aikido can detect patterns such as
// repeated failed logins.
//
// Track only works inside an HTTP request handled by Zen. If it is called
// from a background job, i.e. there is no request in flight, the event is
// not sent and a warning is logged once.
func Track(ctx context.Context, name string, opts ...TrackOption) error {
	var options trackOptions
	for _, opt := range opts {
		opt(&options)
	}

	if config.IsZenDisabled() {
		return nil
	}

	if name == "" {
		return ErrEventNameEmpty
	}

	reqCtx := request.GetContext(ctx)
	if reqCtx == nil {
		trackOutsideRequestWarnOnce.Do(func() {
			log.Warn("zen.Track(...) was called outside of an HTTP request. The event was not sent.")
		})
		return nil
	}

	go agent.OnCustomEvent(name, aikido_types.RequestInfo{
		Method:    reqCtx.Method,
		IPAddress: reqCtx.GetIP(),
		UserAgent: reqCtx.GetUserAgent(),
		URL:       reqCtx.URL,
		Source:    reqCtx.Source,
		Route:     reqCtx.Route,
	}, reqCtx.GetUser())

	return nil
}

// ResetTrackWarnOnce resets the one-time "called outside of an HTTP request"
// warning guard used by Track. Intended for use in tests.
func ResetTrackWarnOnce() {
	trackOutsideRequestWarnOnce = sync.Once{}
}
