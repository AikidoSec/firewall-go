package cloud

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/stretchr/testify/require"
)

func TestLogCloudRequestError(t *testing.T) {
	tests := []struct {
		name         string
		text         string
		err          error
		callCount    int
		expectedLogs int
	}{
		{
			name:         "ErrNoTokenSet logs only once",
			text:         "token error",
			err:          ErrNoTokenSet,
			callCount:    5,
			expectedLogs: 1, // Should only log the first time
		},
		{
			name:         "other errors log every time",
			text:         "network error",
			err:          errors.New("connection failed"),
			callCount:    3,
			expectedLogs: 3, // Should log all 3 times
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset the atomic boolean before each test
			loggedTokenError.Store(false)

			original := log.Logger()

			// Use a custom handler to count log calls
			var buf bytes.Buffer
			handler := slog.NewTextHandler(&buf, nil)
			log.SetLogger(slog.New(handler))

			// Call the function multiple times
			for i := 0; i < tt.callCount; i++ {
				logCloudRequestError(tt.text, tt.err)
			}

			// Count the number of log entries
			logCount := strings.Count(buf.String(), "level=WARN")

			require.Equal(t, tt.expectedLogs, logCount)

			// Restore original logger
			log.SetLogger(original)
		})
	}

	t.Run("different errors after ErrNoTokenSet still log", func(t *testing.T) {
		loggedTokenError.Store(false)
		original := log.Logger()

		var buf bytes.Buffer
		handler := slog.NewTextHandler(&buf, nil)
		log.SetLogger(slog.New(handler))

		logCloudRequestError("token error", ErrNoTokenSet)
		logCloudRequestError("token error again", ErrNoTokenSet) // should be suppressed
		logCloudRequestError("network error", errors.New("connection failed"))
		logCloudRequestError("timeout error", errors.New("timeout"))

		logCount := strings.Count(buf.String(), "level=WARN")
		require.Equal(t, 3, logCount) // token (1) + network (1) + timeout (1)

		log.SetLogger(original)
	})
}
