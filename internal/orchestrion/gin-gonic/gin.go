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
		fmt.Println(c.Params)
		ginContext := context.GetContext(c.Request)
		internal.DefineTransits()
		context.Set(ginContext) // Store context in Thread-Local storage.
		recorder := SetRecorder(c)

		// serve the request to the next middleware
		c.Next()

		fmt.Println("Status code", recorder.StatusCode)
		jsonData, err := json.Marshal(ginContext)
		if err != nil {
			log.Fatalf("Error marshaling to JSON: %v", err)
		}

		// Print the JSON output
		fmt.Println(string(jsonData))

	}
}
