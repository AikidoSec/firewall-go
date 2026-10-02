package cloud

import (
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-([0-9a-f])[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestNewSessionID(t *testing.T) {
	id := NewSessionID()

	matches := uuidPattern.FindStringSubmatch(id)
	if assert.NotNil(t, matches, "should be a valid UUID: %s", id) {
		assert.Equal(t, "7", matches[1], "should be version 7")
	}
	assert.NotEqual(t, NewSessionID(), id, "session IDs should be unique")
}

func TestNewUUIDv7(t *testing.T) {
	before := time.Now().UnixMilli()
	id := newUUIDv7()
	after := time.Now().UnixMilli()

	matches := uuidPattern.FindStringSubmatch(id)
	if assert.NotNil(t, matches, "should be a valid UUID: %s", id) {
		assert.Equal(t, "7", matches[1], "should be version 7")
	}
	assert.NotEqual(t, newUUIDv7(), id, "UUIDs should be unique")

	var ms int64
	for _, c := range id[0:8] + id[9:13] {
		ms = ms<<4 | int64(hexValue(byte(c)))
	}
	assert.GreaterOrEqual(t, ms, before)
	assert.LessOrEqual(t, ms, after)
}

func hexValue(c byte) byte {
	if c >= 'a' {
		return c - 'a' + 10
	}
	return c - '0'
}
