package tests

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStartEvent(t *testing.T) {
	event := waitForEvent(t, 10*time.Second, func(ev map[string]any) bool {
		return ev["type"] == "started"
	})

	assert.Equal(t, "started", event["type"])

	agent, ok := event["agent"].(map[string]any)
	require.True(t, ok)
	assert.NotEmpty(t, agent["hostname"])
	assert.NotEmpty(t, agent["version"])
	assert.NotEmpty(t, agent["library"])
	assert.Equal(t, false, agent["dryMode"])

	eventTime, ok := event["time"].(float64)
	require.True(t, ok)
	assert.WithinDuration(t, time.Now(), time.UnixMilli(int64(eventTime)), 60*time.Second)
}
