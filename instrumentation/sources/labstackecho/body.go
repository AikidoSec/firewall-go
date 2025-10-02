package labstackecho

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/labstack/echo/v4"
)

func tryExtractBody(c echo.Context) any {
	// Try extracting JSON from the raw request :
	bodyFromJSON := tryExtractJSON(c)
	if bodyFromJSON != nil {
		return bodyFromJSON
	}

	bodyFromForm := tryExtractFormBody(c)
	if bodyFromForm != nil {
		return bodyFromForm
	}

	// No use-able data found, returning nil :
	return nil
}

func tryExtractJSON(c echo.Context) any {
	// Read the raw body
	body, err := io.ReadAll(c.Request().Body)
	// Restore body after read
	c.Request().Body = io.NopCloser(bytes.NewBuffer(body))
	if err == nil && len(body) > 0 {
		trimmedBody := strings.TrimSpace(string(body))
		if !strings.HasPrefix(trimmedBody, "{") && !strings.HasPrefix(trimmedBody, "[") {
			return nil
		}
		// Parse :
		var data any
		err = json.Unmarshal(body, &data)
		if err == nil {
			return data
		}
	}
	return nil
}

func tryExtractFormBody(c echo.Context) url.Values {
	if _, err := c.MultipartForm(); err != nil {
		if !errors.Is(err, http.ErrNotMultipart) {
			log.Debugf("(gin) error on parse multipart form array: %v", err)
			return nil
		}
	}
	return c.Request().PostForm
}
