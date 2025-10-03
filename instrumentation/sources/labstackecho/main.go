package labstackecho

import (
	"errors"

	"github.com/AikidoSec/firewall-go/internal"
	"github.com/AikidoSec/firewall-go/internal/context"
	"github.com/AikidoSec/firewall-go/internal/http"
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

			internal.Init()

			ip := c.RealIP()
			echoContext := context.GetContext(httpRequest, c.Path(), "echo")
			echoContext.RemoteAddress = &ip      // use real ip function, which checks x-forwarded-for.
			echoContext.Body = tryExtractBody(c) // Extract body from Echo req

			// Write a possible response (i.e. geo-blocking bot blocking)
			res := http.OnInitRequest(echoContext)
			if res != nil {
				return c.String(res.StatusCode, res.Message)
			}

			err := next(c) // serve the request to the next middleware

			// Report after call with status code :
			status := c.Response().Status

			httpErr := new(echo.HTTPError)
			if errors.As(err, &httpErr) {
				status = httpErr.Code
			}
			http.OnPostRequest(status) // Run post-request logic (should discover route, api spec,...)

			return err
		}
	}
}
