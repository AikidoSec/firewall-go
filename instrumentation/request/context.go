package request

import (
	"context"

	"github.com/AikidoSec/firewall-go/internal/request"
)

type ContextData = request.ContextData

// SetContext sets the context for the given request.
func SetContext(ctx context.Context, data ContextData) context.Context {
	return request.SetContext(ctx, data)
}

// HasContext returns true if the context has a request context set.
func HasContext(ctx context.Context) bool {
	return request.GetContext(ctx) != nil
}

// Wrap calls fn while making the request context available to sinks
// (e.g. database/sql, os/exec) that cannot receive a context.Context directly.
// The request context is only accessible for the duration of fn.
func Wrap(ctx context.Context, fn func()) {
	request.WrapWithGLS(ctx, fn)
}

// EnterGLS is Wrap split into enter/exit, for callers that can't scope the call with a closure.
func EnterGLS(ctx context.Context) func() {
	return request.EnterGLS(ctx)
}
