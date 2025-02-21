package gin_gonic

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/AikidoSec/zen-internals-agent/log"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func tryExtractBody(c gin.Context) interface{} {
	// Try extracting JSON from the raw request :
	bodyFromJson := tryExtractJSON(c)
	if bodyFromJson != nil {
		return bodyFromJson
	}
	bodyFromForm := tryExtractFormBody(c)
	if bodyFromForm != nil {
		return bodyFromForm
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
func tryExtractFormBody(c gin.Context) url.Values {
	if _, err := c.MultipartForm(); err != nil {
		if !errors.Is(err, http.ErrNotMultipart) {
			log.Debugf("(gin) error on parse multipart form array: %v", err)
			return nil
		}
	}
	return c.Request.PostForm
}
