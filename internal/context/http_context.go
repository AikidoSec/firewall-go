package context

import (
	"net/http"
	"strings"
)

func GetContext(r *http.Request, route string, source string) Context {
	return Context{
		URL:            fullURL(r),
		Method:         &r.Method,
		Query:          r.URL.Query(),
		Headers:        headersToMap(r.Header),
		RouteParams:    nil,
		RemoteAddress:  GetRemoteAddress(r),
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

func fullURL(r *http.Request) string {
	// Scheme
	scheme := "http://"
	if r.TLS != nil {
		scheme = "https://"
	}
	//Query
	query := ""
	if len(r.URL.RawQuery) > 0 {
		query = "?" + r.URL.RawQuery
	}
	// Fragment
	fragment := ""
	if len(r.URL.Fragment) > 0 {
		fragment = "#" + r.URL.Fragment
	}

	return scheme + r.Host + r.URL.Path + query + fragment
}
