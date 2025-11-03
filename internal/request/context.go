package request

import (
	"sync"
)

type DeferredBlock struct {
	Error error
}

type Context struct {
	URL                string
	Method             string
	Query              map[string][]string
	Headers            map[string][]string
	RouteParams        map[string]string
	RemoteAddress      *string
	Body               any
	Cookies            map[string]string
	Source             string
	Route              string
	executedMiddleware bool
	user               *User

	deferredBlock error

	mu sync.RWMutex
}

func (ctx *Context) GetUserAgent() string {
	if ctx.Headers != nil && len(ctx.Headers["user-agent"]) > 0 {
		return ctx.Headers["user-agent"][0]
	}
	return "unknown"
}

func (ctx *Context) SetUser(user *User) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	ctx.user = user
}

func (ctx *Context) GetUserID() string {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()

	if ctx.user != nil {
		return ctx.user.ID
	}
	return "" // Empty ID
}

// MarkMiddlewareExecuted marks the middleware as executed.
// Returns true if the middleware was not already executed, false otherwise.
func (ctx *Context) MarkMiddlewareExecuted() bool {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	if ctx.executedMiddleware {
		return false
	}

	ctx.executedMiddleware = true
	return true
}

func (ctx *Context) HasMiddlewareExecuted() bool {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()

	return ctx.executedMiddleware
}

func (ctx *Context) GetIP() string {
	if ctx.RemoteAddress != nil {
		return *ctx.RemoteAddress
	}
	return ""
}

// SetDeferredBlock allows for blocking later in the request flow on vulnerable code paths.
// This allows for detecting attacks on functions that don't return errors, such as `filepath.Join`.
func (ctx *Context) SetDeferredBlock(err error) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	ctx.deferredBlock = err
}

func (ctx *Context) GetDeferredBlock() error {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()

	return ctx.deferredBlock
}
