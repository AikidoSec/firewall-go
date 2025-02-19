package context

import (
	"net/http"
	"strings"
)

func GetContext(r *http.Request, route string, source string) Context {
	url := r.URL.String()
	if len(route) == 0 {
		route = r.URL.Path // Use path from URL as default.
	}
	return Context{
		URL:            &url,
		Method:         &r.Method,
		Query:          r.URL.Query(),
		Headers:        headersToMap(r.Header),
		RouteParams:    nil,
		RemoteAddress:  &r.RemoteAddr,
		Body:           nil,
		Cookies:        cookiesToMap(r.Cookies()),
		AttackDetected: nil,
		Source:         source,
		Route:          route,
		Subdomains:     []string{},
	}
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
