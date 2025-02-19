package labstack_echo

import (
	"encoding/json"
	"github.com/AikidoSec/firewall-go/internal"
	"github.com/AikidoSec/firewall-go/internal/context"
	functions "github.com/AikidoSec/firewall-go/internal/http_functions"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/labstack/echo"
)

// GetMiddleware returns middleware that will create contexts of incoming requests. If service is empty then the
// default service name will be used.
func GetMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			internal.Init()
			httpRequest := c.Request()
			if httpRequest == nil {
				return next(c) // Do not continue.
			}
			echoContext := context.GetContext(httpRequest, "echo")

			functions.OnInitRequest(echoContext)
			err := next(c)               // serve the request to the next middleware
			functions.OnPostRequest(200) // Run post-request logic (should discover route, api spec,...)

			jsonData, err := json.Marshal(echoContext)
			if err != nil {
				log.Errorf("Error marshaling to JSON: %v", err)
			}

			// Print the JSON output
			log.Debug(string(jsonData))
			return err
		}
	}
}
