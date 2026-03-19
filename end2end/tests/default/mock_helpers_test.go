package tests

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func appURL() string {
	if u := os.Getenv("APP_URL"); u != "" {
		return u
	}
	return "http://localhost:8080"
}

func appSQLDialect() string {
	return os.Getenv("APP_SQL_DIALECT")
}

func mockServerURL() string {
	return os.Getenv("MOCK_SERVER_URL")
}

func fetchEvents(t *testing.T) []map[string]any {
	t.Helper()
	resp, err := http.Get(mockServerURL() + "/mock/events")
	require.NoError(t, err)
	defer resp.Body.Close()

	var events []map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&events))
	return events
}

func waitForEvent(t *testing.T, timeout time.Duration, pred func(map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, ev := range fetchEvents(t) {
			if pred(ev) {
				return ev
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("timed out waiting for expected event")
	return nil
}
