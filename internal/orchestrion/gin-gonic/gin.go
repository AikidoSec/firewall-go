package gin_gonic

import (
	"fmt"
	"github.com/AikidoSec/firewall-go/internal/context"
	"github.com/gin-gonic/gin"
	"net/http"
)

// GetMiddleware returns middleware that will create contexts of incoming requests. If service is empty then the
// default service name will be used.
func GetMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// serve the request to the next middleware
		fmt.Println(c.Request)
		fmt.Println(c.Request.URL.Query())
		c.Next()
		ginContext := context.Context{
			URL:            c.Request.URL,
			Method:         &c.Request.Method,
			Query:          c.Request.URL.Query(),
			Headers:        headersToMap(c.Request.Header),
			RouteParams:    nil,
			Body:           nil,
			Cookies:        cookiesToMap(c.Request.Cookies()),
			AttackDetected: nil,
			Source:         "gin",
			Route:          nil,
			Subdomains:     []string{},
		}
		fmt.Println(ginContext)
	}
}

func headersToMap(headers http.Header) map[string][]string {
	headerInfo := make(map[string][]string)
	for key, values := range headers {
		headerInfo[key] = values
	}
	return headerInfo
}

func cookiesToMap(cookies []*http.Cookie) map[string]string {
	cookieInfo := make(map[string]string)
	for _, cookie := range cookies {
		cookieInfo[cookie.Name] = cookie.Value
	}
	return cookieInfo
}
