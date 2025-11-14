package gin

import (
	"github.com/AikidoSec/firewall-go/internal/http"
	"github.com/AikidoSec/firewall-go/internal/request"
	"github.com/gin-gonic/gin"
)

// GetMiddleware returns middleware that will create contexts of incoming requests. If service is empty then the
// default service name will be used.
func GetMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c == nil {
			return // Don't investigate empty requests.
		}

		ip := c.ClientIP()

		reqCtx := request.SetContext(c.Request.Context(), c.Request, c.FullPath(), "gin", &ip,
			http.TryExtractBody(c.Request, c))
		c.Request = c.Request.WithContext(reqCtx)

		// Write a response using Gin :
		res := http.OnInitRequest(c)
		if res != nil {
			c.String(res.StatusCode, res.Message)
			c.Abort()
			return
		}

		request.WrapWithGLS(reqCtx, func() {
			c.Next()
		})

		statusCode := c.Writer.Status()
		http.OnPostRequest(c, statusCode) // Run post-request logic (should discover route, api spec,...)
	}
}
