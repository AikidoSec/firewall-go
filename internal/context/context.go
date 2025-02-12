package context

import "net/url"

type Context struct {
	URL                *url.URL            `json:"url,omitempty"`
	Method             *string             `json:"method,omitempty"`
	Query              map[string][]string `json:"query"`
	Headers            map[string][]string `json:"headers"`
	RouteParams        map[string]string   `json:"routeParams,omitempty"`
	RemoteAddress      *string             `json:"remoteAddress,omitempty"`
	Body               interface{}         `json:"body"`
	Cookies            map[string]string   `json:"cookies"`
	AttackDetected     *bool               `json:"attackDetected,omitempty"`
	Source             string              `json:"source"`
	Route              *string             `json:"route,omitempty"`
	Subdomains         []string            `json:"subdomains,omitempty"`
	ExecutedMiddleware *bool               `json:"executedMiddleware,omitempty"`
}
