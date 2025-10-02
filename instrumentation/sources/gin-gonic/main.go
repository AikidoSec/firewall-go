package gin_gonic

import (
	"github.com/AikidoSec/firewall-go/internal"
	"github.com/AikidoSec/firewall-go/internal/context"
	"github.com/AikidoSec/firewall-go/internal/http_functions"
	"github.com/gin-gonic/gin"
)

// GetMiddleware returns middleware that will create contexts of incoming requests. If service is empty then the
// default service name will be used.
func GetMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c == nil {
			return // Don't investigate empty requests.
		}
		internal.Init()
		ip := c.ClientIP()

		ginContext := context.GetContext(c.Request, c.FullPath(), "gin")
		ginContext.RemoteAddress = &ip       // Use ClientIP() which parses X-Forwarded-For for us.
		ginContext.Body = tryExtractBody(*c) // Extract body from gin request.
		context.Set(ginContext)              // Store context in Thread-Local storage.

		// Write a response using Gin :
		res := http_functions.OnInitRequest(ginContext)
		if res != nil {
			c.String(res.StatusCode, res.Message)
			c.Abort()
			return
		}

		c.Next() // serve the request to the next middleware

		statusCode := c.Writer.Status()
		http_functions.OnPostRequest(statusCode) // Run post-request logic (should discover route, api spec,...)
	}
}
