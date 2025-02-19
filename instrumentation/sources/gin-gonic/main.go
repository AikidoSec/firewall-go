package gin_gonic

import (
	"encoding/json"
	"fmt"
	"github.com/AikidoSec/firewall-go/internal"
	"github.com/AikidoSec/firewall-go/internal/context"
	"github.com/AikidoSec/firewall-go/internal/http_functions"
	"github.com/gin-gonic/gin"
	"log"
)

// GetMiddleware returns middleware that will create contexts of incoming requests. If service is empty then the
// default service name will be used.
func GetMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		internal.Init()
		ginContext := context.GetContext(c.Request, "gin")

		// Make sure it runs after the request is finished : (defer)
		defer func() {
			statusCode := c.Writer.Status()
			http_functions.OnPostRequest(statusCode) // Run post-request logic (should discover route, api spec,...)
		}()

		http_functions.OnInitRequest(ginContext)
		c.Next() // serve the request to the next middleware

		jsonData, err := json.Marshal(ginContext)
		if err != nil {
			log.Fatalf("Error marshaling to JSON: %v", err)
		}

		// Print the JSON output
		fmt.Println(string(jsonData))

	}
}
