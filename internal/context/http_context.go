package context

import (
	"net/http"
)

func GetContext(r *http.Request) Context {
	url := r.URL.String()
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
		Source:         "gin",
		Route:          nil,
		Subdomains:     []string{},
	}
}
func headersToMap(headers http.Header) map[string][]string {
	headerInfo := make(map[string][]string)
	for key, values := range headers {
		headerInfo[key] = values
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
