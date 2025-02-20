package gin_gonic

import (
	"bytes"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"io"
	"strings"
)

func tryExtractBody(c gin.Context) interface{} {
	// Try extracting JSON from the raw request :
	bodyFromJson := tryExtractJSON(c)
	if bodyFromJson != nil {
		return bodyFromJson
	}

	// No use-able data found, returning nil :
	return nil
}

func tryExtractJSON(c gin.Context) interface{} {
	// Read the raw body
	body, err := io.ReadAll(c.Request.Body)
	// Restore body after read
	c.Request.Body = io.NopCloser(bytes.NewBuffer(body))
	if err == nil && len(body) > 0 {
		trimmedBody := strings.TrimSpace(string(body))
		if !strings.HasPrefix(trimmedBody, "{") && !strings.HasPrefix(trimmedBody, "[") {
			return nil
		}
		// Parse :
		var data interface{}
		err = json.Unmarshal(body, &data)
		if err == nil {
			return data
		}
	}
	return nil
}
