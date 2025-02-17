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
	Route              *string             `json:"route,omitempty"`
	Subdomains         []string            `json:"subdomains,omitempty"`
	ExecutedMiddleware *bool               `json:"executedMiddleware,omitempty"`
	User               *User               `json:"user,omitempty"`
}

func (ctx *Context) GetUserAgent() string {
	if ctx.Headers != nil {
		return ctx.Headers["user-agent"][0]
	}
	return "unknown"
}
func (ctx *Context) GetBodyRaw() string {

	return "" // To be implemented
}
func (ctx *Context) GetUserId() string {
	if ctx.User != nil {
		return ctx.User.Id
	}
	return "" // Empty ID
}
func (ctx *Context) GetURL() string {
	if ctx.URL != nil {
		return *ctx.URL
	}
	return ""
}
func (ctx *Context) GetMethod() string {
	if ctx.Method != nil {
		return *ctx.Method
	}
	return "*"
}
func (ctx *Context) GetIP() string {
	if ctx.RemoteAddress != nil {
		return *ctx.RemoteAddress
	}
	return "0.0.0.0"
}
func (ctx *Context) GetRoute() string {
	if ctx.Route != nil {
		return *ctx.Route
	}
	return ""
}
