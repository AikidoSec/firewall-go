package cloud

import (
	"log/slog"
	"time"

	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/AikidoSec/firewall-go/internal/slidingwindow"
)

const (
	maxAttackDetectedEventsPerInterval = 100
	attackDetectedEventsIntervalInMs   = 60 * 60 * 1000 // 1 hour
)

var attackDetectedEventsWindow = slidingwindow.New(
	attackDetectedEventsIntervalInMs,
	maxAttackDetectedEventsPerInterval)

// shouldSendAttackEvent checks if an attack event can be sent based on rate limiting.
// Side effects: Records the event timestamp if under limit, logs warning if over limit.
// Returns true if the event should be sent, false if rate limited.
func shouldSendAttackEvent() bool {
	currentTime := time.Now().UnixMilli()

	if !attackDetectedEventsWindow.TryRecord(currentTime) {
		log.Warn("Maximum number of attack events exceeded for timeframe",
			slog.Int("max", maxAttackDetectedEventsPerInterval),
			slog.Int("count", attackDetectedEventsWindow.Count(currentTime)),
			slog.Int("interval_ms", attackDetectedEventsIntervalInMs))

		return false
	}

	return true
}
