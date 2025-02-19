package gin_gonic

import (
	"encoding/json"
	"fmt"
	"github.com/AikidoSec/firewall-go/internal"
	"github.com/AikidoSec/firewall-go/internal/context"
	"github.com/gin-gonic/gin"
	"log"
)

// GetMiddleware returns middleware that will create contexts of incoming requests. If service is empty then the
// default service name will be used.
func GetMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		internal.Init()
		ip := c.ClientIP()

		ginContext := context.GetContext(c.Request, c.FullPath(), "gin")
		ginContext.RemoteAddress = &ip // Use ClientIP() which parses X-Forwarded-For for us.
		context.Set(ginContext) // Store context in Thread-Local storage.

		// Make sure it runs after the request is finished : (defer)
		defer func() {
			statusCode := c.Writer.Status()
			fmt.Println("Status code", statusCode)
		}()

		// serve the request to the next middleware
		c.Next()

		jsonData, err := json.Marshal(ginContext)
		if err != nil {
			log.Fatalf("Error marshaling to JSON: %v", err)
		}

		// Print the JSON output
		fmt.Println(string(jsonData))

	}
}
