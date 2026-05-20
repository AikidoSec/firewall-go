package testutil

import (
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/AikidoSec/firewall-go/internal/request"
)

var glsFallbackOnce sync.Once

// RegisterGLSFallback installs a goid-keyed GLS implementation for tests
// not run under zen-go toolexec. Idempotent; safe to call from any TestMain.
func RegisterGLSFallback() {
	glsFallbackOnce.Do(func() {
		var m sync.Map
		request.RegisterGLS(
			func() interface{} {
				v, _ := m.Load(goid())
				return v
			},
			func(v interface{}) {
				id := goid()
				if v == nil {
					m.Delete(id)
					return
				}
				m.Store(id, v)
			},
		)
	})
}

func goid() int64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	s := strings.TrimPrefix(string(buf[:n]), "goroutine ")
	idx := strings.IndexByte(s, ' ')
	if idx < 0 {
		return 0
	}
	id, _ := strconv.ParseInt(s[:idx], 10, 64)
	return id
}
