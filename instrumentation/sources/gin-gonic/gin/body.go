package gin

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	zenhttp "github.com/AikidoSec/firewall-go/internal/http"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/gin-gonic/gin"
)

func tryExtractBody(c *gin.Context) any {
	// Try extracting JSON from the raw request :
	bodyFromJSON := zenhttp.TryExtractJSON(c.Request)
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

func tryExtractFormBody(c *gin.Context) url.Values {
	if _, err := c.MultipartForm(); err != nil {
		if !errors.Is(err, http.ErrNotMultipart) {
			log.Debug("(gin) error on parse multipart form array", slog.Any("error", err))
			return nil
		}
	}
	return c.Request.PostForm
}
