package context

type Context struct {
	URL                *string             `json:"url,omitempty"`
	Method             *string             `json:"method,omitempty"`
	Query              map[string][]string `json:"query"`
	Headers            map[string][]string `json:"headers"`
	RouteParams        map[string]string   `json:"routeParams,omitempty"`
	RemoteAddress      *string             `json:"remoteAddress,omitempty"`
	Body               interface{}         `json:"body"`
	Cookies            map[string]string   `json:"cookies"`
	AttackDetected     *bool               `json:"attackDetected,omitempty"`
	Source             string              `json:"source"`
	Route              string              `json:"route,omitempty"`
	Subdomains         []string            `json:"subdomains,omitempty"`
	ExecutedMiddleware *bool               `json:"executedMiddleware,omitempty"`
}

func (ctx *Context) GetUserAgent() string {
	return "to be implemented" // To be implemented
}
func (ctx *Context) GetBodyRaw() string {
	return "to be implemented" // To be implemented
}
func (ctx *Context) GetUserId() string {
	return "to be implemented" // To be implemented
}
