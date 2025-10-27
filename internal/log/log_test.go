package log

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetLogLevelMapping(t *testing.T) {
	prev := levelVar.Level()
	t.Cleanup(func() { levelVar.Set(prev) })

	require.NoError(t, SetLogLevel("debug"))
	assert.Equal(t, slog.LevelDebug, levelVar.Level())

	require.NoError(t, SetLogLevel("INFO"))
	assert.Equal(t, slog.LevelInfo, levelVar.Level())

	require.NoError(t, SetLogLevel("warn"))
	assert.Equal(t, slog.LevelWarn, levelVar.Level())

	require.NoError(t, SetLogLevel("ERR"))
	assert.Equal(t, slog.LevelError, levelVar.Level())

	err := SetLogLevel("nope")
	require.Error(t, err)
}

func TestLevelFilteringWithSlog(t *testing.T) {
	original := logger
	t.Cleanup(func() { logger = original })

	var buf bytes.Buffer
	h := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	SetLogger(slog.New(h))

	// Below threshold
	Debug("nope")
	assert.Equal(t, "", buf.String())

	// Meets threshold
	Info("yes")
	out := buf.String()
	assert.Contains(t, out, "yes")
}

func TestSetLogger(t *testing.T) {
	original := Logger()
	defer SetLogger(original)

	t.Run("adds lib attribute", func(t *testing.T) {
		original := logger
		t.Cleanup(func() { logger = original })

		var buf bytes.Buffer
		h := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
		SetLogger(slog.New(h))

		Info("hello")

		out := buf.String()
		require.NotEmpty(t, out)
		assert.Contains(t, out, "lib=aikido")
		assert.Contains(t, out, "hello")
	})

	t.Run("ignores nil logger", func(t *testing.T) {
		before := Logger()
		SetLogger(nil)
		require.Equal(t, before, Logger(), "logger should not change when SetLogger receives nil")
	})
}
