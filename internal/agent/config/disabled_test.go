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
