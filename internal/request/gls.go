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
	if glsSet == nil {
		fn()
		return
	}

	state := glsStateFor(ctx)
	if state == nil {
		fn()
		return
	}

	prev := glsGet()
	glsSet(state)
	defer glsSet(prev)
	fn()
}
