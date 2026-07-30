package request

import (
	"context"

	"github.com/AikidoSec/firewall-go/internal/request"
)

type ContextData struct {
	Source        string
	Route         string
	RouteParams   map[string]string
	RemoteAddress *string
	Body          any
	URL           string
	Path          string
	Method        string
	Query         map[string][]string
	Headers       map[string][]string
	Cookies       map[string][]string
}

// SetContext sets the context for the given request.
func SetContext(ctx context.Context, data ContextData) context.Context {
	return request.SetContext(ctx, request.ContextData{
		Source:        data.Source,
		Route:         data.Route,
		RouteParams:   data.RouteParams,
		RemoteAddress: data.RemoteAddress,
		Body:          data.Body,
		URL:           data.URL,
		Path:          data.Path,
		Method:        data.Method,
		Query:         data.Query,
		Headers:       data.Headers,
		Cookies:       data.Cookies,
	})
}

// HasContext returns true if the context has a request context set.
func HasContext(ctx context.Context) bool {
	return request.GetContext(ctx) != nil
}

// Wrap calls fn while making the request context available to sinks
// (e.g. database/sql, os/exec) that cannot receive a context.Context directly.
// The request context is only accessible for the duration of fn.
func Wrap(ctx context.Context, fn func()) {
	request.WrapWithGLS(ctx, fn)
}
