package config_test

import (
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/config"
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
