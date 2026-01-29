package http

import (
	"mime/multipart"
	"net/http"
	"strings"
	"sync/atomic"

	zenhttp "github.com/AikidoSec/firewall-go/internal/http"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/zen"
)

// Middleware sets the request contexts of incoming requests.
// It is part of the automatic instrumentation and will be run before any other middleware.
func Middleware(orig func(w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if !zen.ShouldProtect() {
			orig(w, r)
			return
		}

		ip := r.RemoteAddr

		pattern := r.Pattern
		// ServeMux patterns can start with the method and/or host
		// We only care about the path, we need to strip it
		pattern = strings.TrimPrefix(pattern, r.Method+" ")

		// Strip host prefix (e.g., "example.com/path")
		// In Go's ServeMux, paths always start with "/" when there's no host.
		// If the first "/" is at position > 0, it means there's a host prefix before it.
		if idx := strings.Index(pattern, "/"); idx > 0 {
			pattern = pattern[idx:]
		}

		ctx := request.SetContext(r.Context(), r, request.ContextData{
			Source:        "http.ServeMux",
			Route:         pattern,
			RouteParams:   extractRouteParams(r, pattern),
			RemoteAddress: &ip,
			Body:          zenhttp.TryExtractBody(r, &requestParser{req: r}),
		})

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

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	log.Debug("response writer unwrapped, api spec may be lost")
	return r.writer
}

func (r *statusRecorder) WriteHeader(statusCode int) {
	// Only capture the first status code written.
	// WriteHeader can be called multiple times, but only the first call matters.
	if r.written.CompareAndSwap(false, true) {
		r.statusCode = statusCode
	}
	r.writer.WriteHeader(statusCode)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	// If WriteHeader was never called, the status code defaults to 200 OK
	if r.written.CompareAndSwap(false, true) {
		r.statusCode = http.StatusOK
	}
	return r.writer.Write(b)
}

func (r *statusRecorder) Header() http.Header {
	return r.writer.Header()
}

type requestParser struct {
	req *http.Request
}

func (rp *requestParser) MultipartForm() (*multipart.Form, error) {
	// Used same max memory as stdlib:
	// https://cs.opensource.google/go/go/+/refs/tags/go1.25.5:src/net/http/request.go;l=36
	err := rp.req.ParseMultipartForm(32 << 20)
	if err != nil {
		return nil, err
	}

	return rp.req.MultipartForm, nil
}

func extractRouteParams(r *http.Request, pattern string) map[string]string {
	params := make(map[string]string)

	remaining := pattern

	// Find all wildcard parameters in the pattern
	// Pattern examples: "/users/{id}", "/posts/{id}/comments/{commentId}", "/files/{path...}"
	for {
		start := strings.Index(remaining, "{")
		if start == -1 {
			break
		}
		end := strings.Index(remaining[start:], "}")
		if end == -1 {
			break
		}

		paramName := remaining[start+1 : start+end]
		// Strip "..." suffix for multi-segment wildcards
		paramName = strings.TrimSuffix(paramName, "...")
		// Use PathValue to get the actual value from the request
		params[paramName] = r.PathValue(paramName)

		remaining = remaining[start+end+1:]
	}

	return params
}
