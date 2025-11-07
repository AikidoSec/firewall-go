package http

import (
	"net/http"
	"strings"
	"sync/atomic"

	zenhttp "github.com/AikidoSec/firewall-go/internal/http"
	"github.com/AikidoSec/firewall-go/internal/request"
)

// Middleware sets the request contexts of incoming requests.
// It is part of the automatic instrumentation and will be run before any other middleware.
func Middleware(orig func(w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr

		pattern := r.Pattern
		// ServeMux patterns can start with the method and/or host
		// We only care about the path, we need to strip it
		pattern = strings.TrimPrefix(pattern, r.Method+" ")

		// Strip host prefix (e.g., "example.com/path")
		if idx := strings.Index(pattern, "/"); idx > 0 {
			pattern = pattern[idx:]
		}

		ctx := request.SetContext(r.Context(), r, pattern, "ServeMux", &ip, tryExtractBody(r))
		wrappedR := r.WithContext(ctx)

		res := zenhttp.OnInitRequest(ctx)
		if res != nil {
			w.WriteHeader(res.StatusCode)
			_, _ = w.Write([]byte(res.Message))
			return
		}

		// Wrap the ResponseWriter to capture the status code
		recorder := &statusRecorder{
			writer: w,
		}

		request.WrapWithGLS(ctx, func() {
			orig(recorder, wrappedR)
		})

		zenhttp.OnPostRequest(ctx, recorder.statusCode)
	}
}

func WrapHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(Middleware(handler.ServeHTTP))
}

type statusRecorder struct {
	writer     http.ResponseWriter
	statusCode int
	written    atomic.Bool
}

func (r *statusRecorder) WriteHeader(statusCode int) {
	if r.written.CompareAndSwap(false, true) {
		r.statusCode = statusCode
	}
	r.writer.WriteHeader(statusCode)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.written.CompareAndSwap(false, true) {
		r.statusCode = http.StatusOK
	}
	return r.writer.Write(b)
}

func (r *statusRecorder) Header() http.Header {
	return r.writer.Header()
}
