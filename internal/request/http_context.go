package request

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"strings"

	"github.com/AikidoSec/firewall-go/internal/agent/config"
)

type contextKey struct{}

var reqCtxKey contextKey

type ContextData struct {
	Source        string
	Route         string
	RouteParams   map[string]string
	RemoteAddress *string
	Body          any
}

func SetContext(ctx context.Context, r *http.Request, data ContextData) context.Context {
	if data.RemoteAddress != nil && config.IsIPBypassed(*data.RemoteAddress) {
		return ctx
	}

	route := data.Route
	if route == "" {
		route = r.URL.Path // Use path from URL as default.
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
		URL:                fullURL(r),
		Path:               r.URL.Path,
		Method:             r.Method,
		Query:              r.URL.Query(),
		Headers:            headersToMap(r.Header),
		RouteParams:        routeParams,
		RemoteAddress:      data.RemoteAddress,
		Body:               data.Body,
		Cookies:            cookiesToMap(r.Cookies()),
		Source:             data.Source,
		Route:              route,
		executedMiddleware: false, // We start with no middleware executed.
	}
	return context.WithValue(ctx, reqCtxKey, c)
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

func headersToMap(headers http.Header) map[string][]string {
	headerInfo := make(map[string][]string)
	for key, values := range headers {
		if strings.ToLower(key) == "cookie" {
			continue // Ignore cookie header, because we already extract below.
		}
		headerInfo[strings.ToLower(key)] = values
	}
	return headerInfo
}

func cookiesToMap(cookies []*http.Cookie) map[string]string {
	cookieInfo := make(map[string]string)
	for _, cookie := range cookies {
		cookieInfo[cookie.Name] = cookie.Value
	}
	return cookieInfo
}

func fullURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.RequestURI())
}
