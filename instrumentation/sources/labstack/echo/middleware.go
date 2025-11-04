package echo

import (
	"errors"

	"github.com/AikidoSec/firewall-go/internal/http"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/labstack/echo/v4"
)

// GetMiddleware returns middleware that will create contexts of incoming requests. If service is empty then the
// default service name will be used.
func GetMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			httpRequest := c.Request()
			if httpRequest == nil {
				return next(c) // Do not continue.
			}

			ip := c.RealIP()
			reqCtx := request.SetContext(httpRequest.Context(), httpRequest, c.Path(), "echo", &ip, tryExtractBody(c))
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
			status := c.Response().Status

			httpErr := new(echo.HTTPError)
			if errors.As(err, &httpErr) {
				status = httpErr.Code
			}
			http.OnPostRequest(c.Request().Context(), status) // Run post-request logic (should discover route, api spec,...)

			return err
		}
	}
}
