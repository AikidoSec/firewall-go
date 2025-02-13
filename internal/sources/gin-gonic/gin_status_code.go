package gin_gonic

import "github.com/gin-gonic/gin"

type StatusRecorder struct {
	gin.ResponseWriter
	StatusCode int
}

// WriteHeader captures the status code.
func (sr *StatusRecorder) WriteHeader(code int) {
	sr.StatusCode = code
	sr.ResponseWriter.WriteHeader(code)
}

func SetRecorder(c *gin.Context) *StatusRecorder {
	recorder := &StatusRecorder{ResponseWriter: c.Writer}
	c.Writer = recorder
	return recorder
}
