package state

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMiddlewareInstalled(t *testing.T) {
	tests := []struct {
		name     string
		setValue bool
		expected bool
	}{
		{
			name:     "sets middleware as installed",
			setValue: true,
			expected: true,
		},
		{
			name:     "sets middleware as not installed",
			setValue: false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCollector()
			c.SetMiddlewareInstalled(tt.setValue)
			assert.Equal(t, tt.expected, c.IsMiddlewareInstalled())
		})
	}
}

func TestMiddlewareInstalledDefaultState(t *testing.T) {
	c := NewCollector()
	assert.False(t, c.IsMiddlewareInstalled(), "should default to not installed")
}

func TestMiddlewareInstalledToggle(t *testing.T) {
	c := NewCollector()

	assert.False(t, c.IsMiddlewareInstalled(), "should start as not installed")

	c.SetMiddlewareInstalled(true)
	assert.True(t, c.IsMiddlewareInstalled(), "should be installed after setting to true")

	c.SetMiddlewareInstalled(false)
	assert.False(t, c.IsMiddlewareInstalled(), "should be not installed after setting to false")

	c.SetMiddlewareInstalled(true)
	assert.True(t, c.IsMiddlewareInstalled(), "should be installed again after setting to true")
}
