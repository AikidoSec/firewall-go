package log

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"os"
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

	require.NoError(t, SetLogLevel("WARNING"))
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

func TestLogLevels(t *testing.T) {
	tests := []struct {
		name      string
		logFunc   func(string, ...any)
		slogLevel slog.Level
		levelStr  string
		message   string
		args      []any
	}{
		{
			name:      "debug",
			logFunc:   Debug,
			slogLevel: slog.LevelDebug,
			levelStr:  "DEBUG",
			message:   "debug message",
			args:      []any{"key", "value"},
		},
		{
			name:      "info",
			logFunc:   Info,
			slogLevel: slog.LevelInfo,
			levelStr:  "INFO",
			message:   "info message",
			args:      []any{"key", "value"},
		},
		{
			name:      "warn",
			logFunc:   Warn,
			slogLevel: slog.LevelWarn,
			levelStr:  "WARN",
			message:   "warning message",
			args:      []any{"key", "value"},
		},
		{
			name:      "error",
			logFunc:   Error,
			slogLevel: slog.LevelError,
			levelStr:  "ERROR",
			message:   "error message",
			args:      []any{"key", "value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := logger
			t.Cleanup(func() { logger = original })

			var buf bytes.Buffer
			h := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: tt.slogLevel})
			SetLogger(slog.New(h))

			tt.logFunc(tt.message, tt.args...)
			out := buf.String()

			// Verify message and args
			assert.Contains(t, out, tt.message)
			assert.Contains(t, out, "key=value")

			// Verify the correct level appears in output
			assert.Contains(t, out, "level="+tt.levelStr)
		})
	}
}

func TestSetFormat(t *testing.T) {
	originalFormat := logFormat
	originalWriter := logWriter
	t.Cleanup(func() {
		logFormat = originalFormat
		logWriter = originalWriter
		rebuildLogger()
	})

	t.Run("text format", func(t *testing.T) {
		err := SetFormat("text")
		require.NoError(t, err)
		assert.Equal(t, "text", logFormat)

		// Verify logger still works after format change
		original := logger
		t.Cleanup(func() { logger = original })

		var buf bytes.Buffer
		h := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
		SetLogger(slog.New(h))

		Info("test message")
		out := buf.String()
		assert.Contains(t, out, "test message")
		assert.Contains(t, out, "lib=aikido")
	})

	t.Run("console format (aliased to text)", func(t *testing.T) {
		err := SetFormat("console")
		require.NoError(t, err)
		assert.Equal(t, "text", logFormat)
	})

	t.Run("json format", func(t *testing.T) {
		r, w, err := os.Pipe()
		require.NoError(t, err)

		oldWriter := logWriter
		logWriter = w
		defer func() {
			logWriter = oldWriter
			w.Close()
			r.Close()
		}()

		// Read from pipe in goroutine to avoid blocking
		var buf bytes.Buffer
		done := make(chan struct{})
		go func() {
			_, _ = io.Copy(&buf, r)
			close(done)
		}()

		err = SetFormat("json")
		require.NoError(t, err)
		assert.Equal(t, "json", logFormat)

		Info("test message", "key", "value")
		w.Close()
		<-done

		// Parse each line as JSON (slog outputs one JSON object per line)
		lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
		require.Greater(t, len(lines), 0, "should have at least one log line")

		for _, line := range lines {
			var logEntry map[string]any
			err := json.Unmarshal(line, &logEntry)
			require.NoError(t, err, "output should be valid JSON: %s", string(line))

			// Verify expected fields
			assert.Equal(t, "test message", logEntry["msg"])
			assert.Equal(t, "aikido", logEntry["lib"])
			assert.Equal(t, "value", logEntry["key"])
		}
	})

	t.Run("invalid format", func(t *testing.T) {
		err := SetFormat("invalid")
		require.Error(t, err)
		assert.Equal(t, "invalid log format", err.Error())
	})

	t.Run("trimmed format", func(t *testing.T) {
		err := SetFormat("  JSON  ")
		require.NoError(t, err)
		assert.Equal(t, "json", logFormat)
	})
}

func TestToSlogLevel(t *testing.T) {
	assert.Equal(t, slog.LevelDebug, toSlogLevel(DebugLevel))
	assert.Equal(t, slog.LevelInfo, toSlogLevel(InfoLevel))
	assert.Equal(t, slog.LevelWarn, toSlogLevel(WarnLevel))
	assert.Equal(t, slog.LevelError, toSlogLevel(ErrorLevel))

	// Test default case for invalid LogLevel
	assert.Equal(t, slog.LevelInfo, toSlogLevel(LogLevel(99)))
}
