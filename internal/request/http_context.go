package request

import (
	"context"
	"maps"
	"strings"

	"github.com/AikidoSec/firewall-go/internal/agent/config"
)

type contextKey struct{}
type bypassedContextKey struct{}

var reqCtxKey contextKey
var bypassedCtxKey bypassedContextKey

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

func SetContext(ctx context.Context, data ContextData) context.Context {
	if data.RemoteAddress != nil && config.IsIPBypassed(*data.RemoteAddress) {
		return context.WithValue(ctx, bypassedCtxKey, true)
	}

	route := data.Route
	if route == "" {
		route = data.Path // Use path as default.
	}

	// Trim the trailing slashes from route to normalise for matching with API
	if route != "/" {
		route = strings.TrimSuffix(route, "/")
	}

	var routeParams map[string]string
	if data.RouteParams != nil {
		routeParams = maps.Clone(data.RouteParams)
	}

	c := &Context{
		URL:                data.URL,
		Path:               data.Path,
		Method:             data.Method,
		Query:              data.Query,
		Headers:            data.Headers,
		RouteParams:        routeParams,
		RemoteAddress:      data.RemoteAddress,
		Body:               data.Body,
		Cookies:            data.Cookies,
		Source:             data.Source,
		Route:              route,
		executedMiddleware: false, // We start with no middleware executed.
	}
	return context.WithValue(ctx, reqCtxKey, c)
}

func IsBypassed(ctx context.Context) bool {
	if ctx != nil {
		if v := ctx.Value(bypassedCtxKey); v != nil {
			return v.(bool)
		}
	}
	return isLocalBypassed()
}

func GetContext(ctx context.Context) *Context {
	if ctx != nil {
		if c := ctx.Value(reqCtxKey); c != nil {
			return c.(*Context)
		}
	}

	// Fallback to GLS if not found in context
	// This is used when we are protecting a method that doesn't take a context
	// such as `os.OpenFile`.
	return getLocalContext()
}

// EnsureContextPropagated ensures the request context is stored in the Go context.
// If the context already has request data, it returns ctx unchanged.
// Otherwise it checks the GLS fallback and, if found, stores it in the context.
// This is needed to pass request data across goroutine boundaries (e.g. from
// http.RoundTrip to the transport's DialContext which runs in a different goroutine).
func EnsureContextPropagated(ctx context.Context) context.Context {
	if ctx.Value(reqCtxKey) != nil {
		return ctx
	}
	if c := getLocalContext(); c != nil {
		return context.WithValue(ctx, reqCtxKey, c)
	}
	if ctx.Value(bypassedCtxKey) == nil && isLocalBypassed() {
		return context.WithValue(ctx, bypassedCtxKey, true)
	}
	return ctx
}
