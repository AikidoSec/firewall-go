package chi

import (
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/netip"

	zenhttp "github.com/AikidoSec/firewall-go/internal/http"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
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
			if err != nil {
				log.Debug("could not parse ip", slog.Any("error", err))
			} else {
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
			recorder := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			request.WrapWithGLS(reqCtx, func() {
				next.ServeHTTP(recorder, wrappedR)
			})

			zenhttp.OnPostRequest(reqCtx, recorder.Status())
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
