package request

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

type contextKey struct{}

var reqCtxKey contextKey

func SetContext(ctx context.Context, r *http.Request, route string, source string, remoteAddress *string, body any) context.Context {
	if len(route) == 0 {
		route = r.URL.Path // Use path from URL as default.
	}

	c := &Context{
		URL:                fullURL(r),
		Method:             r.Method,
		Query:              r.URL.Query(),
		Headers:            headersToMap(r.Header),
		RouteParams:        nil,
		RemoteAddress:      remoteAddress,
		Body:               body,
		Cookies:            cookiesToMap(r.Cookies()),
		AttackDetected:     nil,
		Source:             source,
		Route:              route,
		Subdomains:         []string{},
		executedMiddleware: false, // We start with no middleware executed.
	}
	return context.WithValue(ctx, reqCtxKey, c)
}

func GetContext(ctx context.Context) *Context {
	c := ctx.Value(reqCtxKey)
	if c == nil {
		return nil
	}

	return c.(*Context)
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
