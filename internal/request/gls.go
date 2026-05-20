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
	v := glsGet()
	if v == nil {
		return nil
	}
	s, _ := v.(*glsState)
	return s
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

// WrapWithGLS keeps the context alive in the GLS until the given function has finished executing.
func WrapWithGLS(ctx context.Context, fn func()) {
	if glsSet == nil {
		fn()
		return
	}

	var state *glsState
	if reqCtx := GetContext(ctx); reqCtx != nil {
		state = &glsState{ctx: reqCtx}
	} else if IsBypassed(ctx) {
		state = &glsState{bypassed: true}
	}

	if state == nil {
		fn()
		return
	}

	prev := glsGet()
	glsSet(state)
	defer glsSet(prev)
	fn()
}
