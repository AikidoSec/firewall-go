package utils

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetTime(t *testing.T) {
	before := time.Now().UnixMilli()
	result := GetTime()
	after := time.Now().UnixMilli()

	assert.GreaterOrEqual(t, result, before)
	assert.LessOrEqual(t, result, after)
}
