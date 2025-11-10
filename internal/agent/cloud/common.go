package cloud

import (
	"errors"
	"log/slog"
	"sync/atomic"

	"github.com/AikidoSec/firewall-go/internal/log"
)

var loggedTokenError atomic.Bool

func logCloudRequestError(text string, err error) {
	if errors.Is(err, ErrNoTokenSet) {
		if !loggedTokenError.CompareAndSwap(false, true) {
			return
		}
	}
	log.Warn(text, slog.Any("error", err))
}
