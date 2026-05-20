// This file is added to the standard library "runtime" package by the
// zen-go toolexec via the add-file rule in zen.instrument.yml. It is NOT
// compiled as part of any normal Go build; the leading underscore in the
// parent directory keeps the Go toolchain from discovering it.
//
// Once injected, it provides accessors for the aikido_request_context field
// that the add-field rule adds to runtime.g, and it registers those accessors
// with firewall-go's internal/request package so the rest of the firewall can
// read and write the per-goroutine value without using a third-party GLS.

package runtime

import _ "unsafe"

//go:linkname aikidoRegisterGLS github.com/AikidoSec/firewall-go/internal/request.RegisterGLS
func aikidoRegisterGLS(get func() interface{}, set func(interface{}))

func aikidoGLSGet() interface{} {
	return getg().m.curg.aikido_request_context
}

func aikidoGLSSet(v interface{}) {
	getg().m.curg.aikido_request_context = v
}

func init() {
	aikidoRegisterGLS(aikidoGLSGet, aikidoGLSSet)
}
