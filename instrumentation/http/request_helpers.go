package http

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/AikidoSec/firewall-go/internal/request"
)

func FullURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.RequestURI())
}

func HeadersToMap(headers http.Header) map[string][]string {
	result := make(map[string][]string, len(headers))
	for key, values := range headers {
		result[strings.ToLower(key)] = values
	}
	return result
}

func CookiesToMap(cookies []*http.Cookie) map[string][]string {
	result := make(map[string][]string)
	for _, cookie := range cookies {
		result[cookie.Name] = append(result[cookie.Name], cookie.Value)
	}
	return result
}

// ContextDataFromRequest extracts the fields request.ContextData derives from
// an *http.Request. Callers set the remaining fields (Source, Route,
// RouteParams, RemoteAddress, Body) before calling request.SetContext.
func ContextDataFromRequest(r *http.Request) request.ContextData {
	return request.ContextData{
		URL:     FullURL(r),
		Path:    r.URL.Path,
		Method:  r.Method,
		Query:   r.URL.Query(),
		Headers: HeadersToMap(r.Header),
		Cookies: CookiesToMap(r.Cookies()),
	}
}
