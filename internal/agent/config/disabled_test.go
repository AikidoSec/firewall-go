package config_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/config"
	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/stretchr/testify/assert"
)

func TestZenDisabled(t *testing.T) {
	config.SetZenDisabled(true)
	assert.True(t, config.IsZenDisabled())

	config.SetZenDisabled(false)
	assert.False(t, config.IsZenDisabled())
}

func TestShouldProtect(t *testing.T) {
	tests := []struct {
		name     string
		disabled bool
		loaded   bool
		want     bool
	}{
		{
			name:     "not loaded and not disabled returns false",
			disabled: false,
			loaded:   false,
			want:     false,
		},
		{
			name:     "loaded and not disabled returns true",
			disabled: false,
			loaded:   true,
			want:     true,
		},
		{
			name:     "not loaded and disabled returns false",
			disabled: true,
			loaded:   false,
			want:     false,
		},
		{
			name:     "loaded but disabled returns false",
			disabled: true,
			loaded:   true,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original state
			origDisabled := config.IsZenDisabled()
			origLoaded := config.IsZenLoaded()
			defer func() {
				config.SetZenDisabled(origDisabled)
				config.SetZenLoaded(origLoaded)
			}()

			// Set test state
			config.SetZenDisabled(tt.disabled)
			config.SetZenLoaded(tt.loaded)

			got := config.ShouldProtect()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWarnIfNotProtected(t *testing.T) {
	saveAndRestore := func(t *testing.T) {
		origDisabled := config.IsZenDisabled()
		origLoaded := config.IsZenLoaded()
		origLogger := log.Logger()
		t.Cleanup(func() {
			config.SetZenDisabled(origDisabled)
			config.SetZenLoaded(origLoaded)
			config.ResetWarnOnce()
			log.SetLogger(origLogger)
		})
	}

	t.Run("warns when not loaded and not disabled", func(t *testing.T) {
		saveAndRestore(t)

		var buf bytes.Buffer
		log.SetLogger(slog.New(slog.NewTextHandler(&buf, nil)))
		config.SetZenDisabled(false)
		config.SetZenLoaded(false)

		config.WarnIfNotProtected()

		assert.Equal(t, 1, strings.Count(buf.String(), "level=WARN"))
		assert.Contains(t, buf.String(), "zen.Protect() was not called")
	})

	t.Run("does not warn when disabled", func(t *testing.T) {
		saveAndRestore(t)

		var buf bytes.Buffer
		log.SetLogger(slog.New(slog.NewTextHandler(&buf, nil)))
		config.SetZenDisabled(true)
		config.SetZenLoaded(false)

		config.WarnIfNotProtected()

		assert.Equal(t, 0, strings.Count(buf.String(), "level=WARN"))
	})

	t.Run("does not warn when loaded", func(t *testing.T) {
		saveAndRestore(t)

		var buf bytes.Buffer
		log.SetLogger(slog.New(slog.NewTextHandler(&buf, nil)))
		config.SetZenDisabled(false)
		config.SetZenLoaded(true)

		config.WarnIfNotProtected()

		assert.Equal(t, 0, strings.Count(buf.String(), "level=WARN"))
	})

	t.Run("warns only once", func(t *testing.T) {
		saveAndRestore(t)

		var buf bytes.Buffer
		log.SetLogger(slog.New(slog.NewTextHandler(&buf, nil)))
		config.SetZenDisabled(false)
		config.SetZenLoaded(false)

		config.WarnIfNotProtected()
		config.WarnIfNotProtected()
		config.WarnIfNotProtected()

		assert.Equal(t, 1, strings.Count(buf.String(), "level=WARN"))
	})
}
