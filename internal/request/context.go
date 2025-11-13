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

	deferredAttack *DeferredAttack

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

// DeferredAttack stores attack information and error to be reported/blocked later
type DeferredAttack struct {
	Operation     string
	Kind          string
	Source        string
	PathToPayload string
	Metadata      map[string]string
	Payload       string
	Error         error // The error to return if blocking is enabled
}

// SetDeferredAttack allows for reporting attacks later in the request flow.
// This allows for detecting attacks on functions that don't return errors, such as `filepath.Join`.
func (ctx *Context) SetDeferredAttack(attack *DeferredAttack) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	ctx.deferredAttack = attack
}

func (ctx *Context) GetDeferredAttack() *DeferredAttack {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()

	return ctx.deferredAttack
}
