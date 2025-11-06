package http

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	zenhttp "github.com/AikidoSec/firewall-go/internal/http"
	"github.com/AikidoSec/firewall-go/internal/log"
)

func tryExtractBody(r *http.Request) any {
	bodyFromJSON := zenhttp.TryExtractJSON(r)
	if bodyFromJSON != nil {
		return bodyFromJSON
	}

	bodyFromForm := tryExtractFormBody(r)
	if bodyFromForm != nil {
		return bodyFromForm
	}

	// No usable data found, returning nil
	return nil
}

func tryExtractFormBody(r *http.Request) url.Values {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		if !errors.Is(err, http.ErrNotMultipart) {
			log.Debug("error on parse multipart form", slog.Any("error", err))
			return nil
		}
	}
	return r.PostForm
}
