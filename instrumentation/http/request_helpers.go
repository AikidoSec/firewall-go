package http

import (
	"fmt"
	"net/http"
	"strings"
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
		if strings.ToLower(key) == "cookie" {
			continue
		}
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
