package echo

import (
	"errors"

	"github.com/AikidoSec/firewall-go/internal/http"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/labstack/echo/v5"
)

// GetMiddleware returns middleware that will create contexts of incoming requests. If service is empty then the
// default service name will be used.
func GetMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if !zen.ShouldProtect() {
				return next(c)
			}

			httpRequest := c.Request()
			if httpRequest == nil {
				return next(c)
			}

			ip := c.RealIP()

			var routeParams map[string]string
			if len(c.PathValues()) > 0 {
				routeParams = make(map[string]string, len(c.PathValues()))

				for _, pv := range c.PathValues() {
					routeParams[pv.Name] = pv.Value
				}
			}

			reqCtx := request.SetContext(httpRequest.Context(), httpRequest, request.ContextData{
				Source:        "echo",
				Route:         c.Path(),
				RouteParams:   routeParams,
				RemoteAddress: &ip,
				Body:          http.TryExtractBody(httpRequest, c),
			})
			c.SetRequest(httpRequest.WithContext(reqCtx))

			// Write a possible response (i.e. geo-blocking bot blocking)
			res := http.OnInitRequest(c.Request().Context())
			if res != nil {
				return c.String(res.StatusCode, res.Message)
			}

			var err error
			request.WrapWithGLS(reqCtx, func() {
				err = next(c)
			})

			// Report after call with status code :
			// @todo err
			response, _ := echo.UnwrapResponse(c.Response())
			status := response.Status

			httpErr := new(echo.HTTPError)
			if errors.As(err, &httpErr) {
				status = httpErr.Code
			}
			http.OnPostRequest(c.Request().Context(), status) // Run post-request logic (should discover route, api spec,...)

			return err
		}
	}
}
