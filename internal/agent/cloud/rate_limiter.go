package cloud

import (
	"log/slog"
	"sync"
	"time"

	"github.com/AikidoSec/firewall-go/internal/log"
)

var (
	// Holds times at which attacks were reported
	// This allows us to limit the maximum number of attacks reported within a window of time
	attackDetectedEventsSentAt      []int64
	attackDetectedEventsSentAtMutex sync.Mutex
)

const (
	maxAttackDetectedEventsPerInterval = 100
	attackDetectedEventsIntervalInMs   = 60 * 60 * 1000 // 1 hour
)

// shouldSendAttackEvent checks if an attack event can be sent based on rate limiting.
// Side effects: Records the event timestamp if under limit, logs warning if over limit.
// Returns true if the event should be sent, false if rate limited.
func shouldSendAttackEvent() bool {
	attackDetectedEventsSentAtMutex.Lock()
	defer attackDetectedEventsSentAtMutex.Unlock()

	currentTime := time.Now().UnixMilli()

	// Filter out events that are outside the current interval
	var filteredEvents []int64
	for _, eventTime := range attackDetectedEventsSentAt {
		if eventTime > currentTime-attackDetectedEventsIntervalInMs {
			filteredEvents = append(filteredEvents, eventTime)
		}
	}
	attackDetectedEventsSentAt = filteredEvents

	if len(attackDetectedEventsSentAt) >= maxAttackDetectedEventsPerInterval {
		log.Warn("Maximum number of attack events exceeded for timeframe",
			slog.Int("max", maxAttackDetectedEventsPerInterval),
			slog.Int("count", len(attackDetectedEventsSentAt)),
			slog.Int("interval_ms", attackDetectedEventsIntervalInMs))

		return false
	}

	attackDetectedEventsSentAt = append(attackDetectedEventsSentAt, currentTime)
	return true
}
