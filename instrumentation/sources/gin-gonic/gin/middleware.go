package gin

import (
	"github.com/AikidoSec/firewall-go/instrumentation/http"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/gin-gonic/gin"
)

// GetMiddleware returns middleware that will create contexts of incoming requests. If service is empty then the
// default service name will be used.
func GetMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c == nil {
			return // Don't investigate empty requests.
		}

		if !zen.ShouldProtect() {
			zen.WarnIfNotProtected()
			c.Next()
			return
		}

		ip := c.ClientIP()

		var routeParams map[string]string
		if len(c.Params) > 0 {
			routeParams = make(map[string]string, len(c.Params))

			for _, v := range c.Params {
				routeParams[v.Key] = v.Value
			}
		}

		reqCtx := request.SetContext(c.Request.Context(), c.Request, request.ContextData{
			Source:        "gin",
			Route:         c.FullPath(),
			RouteParams:   routeParams,
			RemoteAddress: &ip,
			Body:          http.TryExtractBody(c.Request, c),
		})
		c.Request = c.Request.WithContext(reqCtx)

		// Write a response using Gin :
		res := http.OnInitRequest(c)
		if res != nil {
			c.String(res.StatusCode, res.Message)
			c.Abort()
			return
		}

		// Run post request in defer to still trigger it on panics
		// It may not run depending where the recovery middleware sits in the middleware chain
		defer func() {
			statusCode := c.Writer.Status()
			http.OnPostRequest(c, statusCode) // Run post-request logic (should discover route, api spec,...)
		}()

		request.WrapWithGLS(reqCtx, func() {
			c.Next()
		})
	}
}
