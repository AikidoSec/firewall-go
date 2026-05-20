package request

import (
	"runtime"
	"strconv"
	"strings"
	"sync"
)

// internal/testutil holds the canonical version of this fallback; it lives
// here too because internal/testutil imports this package, so this package's
// tests can't pull it in without a cycle.

func init() {
	if glsGet != nil {
		return
	}

	var m sync.Map
	RegisterGLS(
		func() interface{} {
			v, _ := m.Load(testGoid())
			return v
		},
		func(v interface{}) {
			id := testGoid()
			if v == nil {
				m.Delete(id)
				return
			}
			m.Store(id, v)
		},
	)
}

func testGoid() int64 {
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
