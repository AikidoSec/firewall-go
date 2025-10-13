package labstackecho

import (
	"errors"
	"net/http"
	"net/url"

	zenhttp "github.com/AikidoSec/firewall-go/internal/http"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/labstack/echo/v4"
)

func tryExtractBody(c echo.Context) any {
	// Try extracting JSON from the raw request :
	bodyFromJSON := zenhttp.TryExtractJSON(c.Request())
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

func tryExtractFormBody(c echo.Context) url.Values {
	if _, err := c.MultipartForm(); err != nil {
		if !errors.Is(err, http.ErrNotMultipart) {
			log.Debugf("(gin) error on parse multipart form array: %v", err)
			return nil
		}
	}
	return c.Request().PostForm
}
