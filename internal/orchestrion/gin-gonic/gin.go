package gin_gonic

import (
	"fmt"
	"github.com/gin-gonic/gin"
)

// GetMiddleware returns middleware that will create contexts of incoming requests. If service is empty then the
// default service name will be used.
func GetMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// serve the request to the next middleware
		fmt.Println(c.Request)
		fmt.Println(c.Request.URL.Query())
		c.Next()
	}
}
