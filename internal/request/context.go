package request

import "encoding/json"

type Context struct {
	URL                string              `json:"url,omitempty"`
	Method             *string             `json:"method,omitempty"`
	Query              map[string][]string `json:"query"`
	Headers            map[string][]string `json:"headers"`
	RouteParams        map[string]string   `json:"routeParams,omitempty"`
	RemoteAddress      *string             `json:"remoteAddress,omitempty"`
	Body               any                 `json:"body"`
	Cookies            map[string]string   `json:"cookies"`
	AttackDetected     *bool               `json:"attackDetected,omitempty"`
	Source             string              `json:"source"`
	Route              string              `json:"route,omitempty"`
	Subdomains         []string            `json:"subdomains,omitempty"`
	ExecutedMiddleware bool                `json:"executedMiddleware"`
	User               *User               `json:"user,omitempty"`
}

func (ctx *Context) GetUserAgent() string {
	if ctx.Headers != nil && len(ctx.Headers["user-agent"]) > 0 {
		return ctx.Headers["user-agent"][0]
	}
	return "unknown"
}

func (ctx *Context) GetBodyRaw() string {
	data, err := json.Marshal(ctx.Body)
	if err != nil {
		return ""
	}
	return string(data)
}

func (ctx *Context) GetUserID() string {
	if ctx.User != nil {
		return ctx.User.ID
	}
	return "" // Empty ID
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
	return ""
}
