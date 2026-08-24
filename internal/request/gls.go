package request

import (
	"context"
)

var (
	glsGet func() interface{}
	glsSet func(interface{})
)

// RegisterGLS is linked from runtime by instrumentation/runtime; renaming
// it requires updating that file's go:linkname directive.
func RegisterGLS(get func() interface{}, set func(interface{})) {
	glsGet = get
	glsSet = set
}

type glsState struct {
	ctx      *Context
	bypassed bool
}

func getGLS() *glsState {
	if glsGet == nil {
		return nil
	}
	raw := glsGet()
	if raw == nil {
		return nil
	}
	state, _ := raw.(*glsState)
	return state
}

func getLocalContext() *Context {
	if s := getGLS(); s != nil {
		return s.ctx
	}
	return nil
}

func isLocalBypassed() bool {
	if s := getGLS(); s != nil {
		return s.bypassed
	}
	return false
}

func glsStateFor(ctx context.Context) *glsState {
	if reqCtx := GetContext(ctx); reqCtx != nil {
		return &glsState{ctx: reqCtx}
	}
	if IsBypassed(ctx) {
		return &glsState{bypassed: true}
	}
	return nil
}

// WrapWithGLS keeps the context alive in the GLS until the given function has finished executing.
func WrapWithGLS(ctx context.Context, fn func()) {
	restore := EnterGLS(ctx)
	defer restore()
	fn()
}

// EnterGLS is WrapWithGLS split into enter/exit, for callers that can't scope the call with a closure.
func EnterGLS(ctx context.Context) func() {
	if glsSet == nil {
		return func() {}
	}

	state := glsStateFor(ctx)
	if state == nil {
		return func() {}
	}

	prev := glsGet()
	glsSet(state)
	return func() { glsSet(prev) }
}
