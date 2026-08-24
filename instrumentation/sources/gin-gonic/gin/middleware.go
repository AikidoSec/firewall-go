package gin

import (
	zenhttp "github.com/AikidoSec/firewall-go/instrumentation/http"
	"github.com/AikidoSec/firewall-go/instrumentation/request"
	"github.com/AikidoSec/firewall-go/zen"
	"github.com/gin-gonic/gin"
)

// GetMiddleware returns middleware that will create contexts of incoming requests. If service is empty then the
// default service name will be used.
//
// Automatic instrumentation calls BeforeNext directly instead of registering this via .Use();
// GetMiddleware remains for manual wiring and tests.
func GetMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		exit, blocked := BeforeNext(c)
		if blocked {
			return
		}

		defer exit()
		c.Next()
	}
}

// BeforeNext runs the zen request-context setup and blocking checks for c, once per request.
// If blocked, a response was already written and the caller must not run any handlers.
// Otherwise the caller must defer the returned exit func to run post-request logic.
func BeforeNext(c *gin.Context) (exit func(), blocked bool) {
	noop := func() {}

	if c == nil {
		return noop, false // Don't investigate empty requests.
	}

	if !zen.ShouldProtect() {
		zen.WarnIfNotProtected()
		return noop, false
	}

	ip := c.ClientIP()

	var routeParams map[string]string
	if len(c.Params) > 0 {
		routeParams = make(map[string]string, len(c.Params))

		for _, v := range c.Params {
			routeParams[v.Key] = v.Value
		}
	}

	data := zenhttp.ContextDataFromRequest(c.Request)
	data.Source = "gin"
	data.Route = c.FullPath()
	data.RouteParams = routeParams
	data.RemoteAddress = &ip
	data.Body = zenhttp.TryExtractBody(c.Request, c)

	reqCtx := request.SetContext(c.Request.Context(), data)
	c.Request = c.Request.WithContext(reqCtx)

	// Write a response using Gin :
	res := zenhttp.OnInitRequest(c)
	if res != nil {
		c.String(res.StatusCode, res.Message)
		c.Abort()
		return noop, true
	}

	restoreGLS := request.EnterGLS(reqCtx)

	return func() {
		restoreGLS()
		zenhttp.OnPostRequest(c, c.Writer.Status()) // Run post-request logic (should discover route, api spec,...)
	}, false
}
