package chi

import (
	"mime/multipart"
	"net/http"
	"net/netip"
	"sync/atomic"

	zenhttp "github.com/AikidoSec/firewall-go/internal/http"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/go-chi/chi/v5"
)

// GetMiddleware returns middleware that will create contexts of incoming requests.
func GetMiddleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r == nil {
				next.ServeHTTP(w, r)
				return
			}

			var ip string
			addrPort, err := netip.ParseAddrPort(r.RemoteAddr)
			if err == nil {
				ip = addrPort.Addr().String()
			}

			routeCtx := chi.RouteContext(r.Context())
			var route string
			var routeParams map[string]string

			if routeCtx != nil {
				var urlParams chi.RouteParams
				route, urlParams = getRoutePattern(r)
				if len(urlParams.Keys) > 0 {
					routeParams = make(map[string]string, len(urlParams.Keys))
					for i, key := range urlParams.Keys {
						if i < len(urlParams.Values) {
							routeParams[key] = urlParams.Values[i]
						}
					}
				}
			}

			reqCtx := request.SetContext(r.Context(), r, request.ContextData{
				Source:        "chi",
				Route:         route,
				RouteParams:   routeParams,
				RemoteAddress: &ip,
				Body:          zenhttp.TryExtractBody(r, &requestParser{req: r}),
			})

			wrappedR := r.WithContext(reqCtx)

			res := zenhttp.OnInitRequest(reqCtx)
			if res != nil {
				w.WriteHeader(res.StatusCode)
				_, _ = w.Write([]byte(res.Message))
				return
			}

			// Wrap the ResponseWriter to capture the status code
			recorder := &statusRecorder{
				writer: w,
			}

			request.WrapWithGLS(reqCtx, func() {
				next.ServeHTTP(recorder, wrappedR)
			})

			zenhttp.OnPostRequest(reqCtx, recorder.statusCode)
		})
	}
}

func getRoutePattern(r *http.Request) (string, chi.RouteParams) {
	rctx := chi.RouteContext(r.Context())
	if pattern := rctx.RoutePattern(); pattern != "" {
		// Pattern is already available
		return pattern, rctx.URLParams
	}

	routePath := r.URL.Path
	if r.URL.RawPath != "" {
		routePath = r.URL.RawPath
	}

	tctx := chi.NewRouteContext()
	if !rctx.Routes.Match(tctx, r.Method, routePath) {
		// No matching pattern, so just return the request path.
		// Depending on your use case, it might make sense to
		// return an empty string or error here instead
		return routePath, rctx.URLParams
	}

	// tctx has the updated pattern, since Match mutates it
	return tctx.RoutePattern(), tctx.URLParams
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
