package request

import (
	"context"

	"github.com/jtolds/gls"
)

var (
	glsManager     *gls.ContextManager
	glsCtxKey      = "ctx"
	glsBypassedKey = "bypassed"
)

func init() {
	glsManager = gls.NewContextManager()
}

// getLocalContext attempts to retrieve the request context for the current goroutine
// This should return the context if it is called within the same callstack as WrapWithGLS
func getLocalContext() *Context {
	if ctx, ok := glsManager.GetValue(glsCtxKey); ok && ctx != nil {
		return ctx.(*Context)
	}

	return nil
}

// isLocalBypassed returns true if the current goroutine is running within a bypassed request.
func isLocalBypassed() bool {
	v, ok := glsManager.GetValue(glsBypassedKey)
	return ok && v == true
}

// WrapWithGLS keeps the context alive in the GLS until the given function has finished executing.
func WrapWithGLS(ctx context.Context, fn func()) {
	reqCtx := GetContext(ctx)
	if reqCtx != nil {
		glsManager.SetValues(gls.Values{
			glsCtxKey: reqCtx,
		}, fn)
		return
	}

	if IsBypassed(ctx) {
		glsManager.SetValues(gls.Values{
			glsBypassedKey: true,
		}, fn)
		return
	}

	fn()
}
