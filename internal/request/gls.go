package request

import (
	"context"

	"github.com/jtolds/gls"
)

var (
	glsManager *gls.ContextManager
	glsCtxKey  = "ctx"
)

func init() {
	glsManager = gls.NewContextManager()
}

func getLocalContext() *Context {
	if ctx, ok := glsManager.GetValue(glsCtxKey); ok && ctx != nil {
		return ctx.(*Context)
	}

	return nil
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

	fn()
}
