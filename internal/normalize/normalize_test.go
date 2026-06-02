package normalize

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHostname(t *testing.T) {
	assert.Equal(t, "example.com", Hostname("example.com."))
	assert.Equal(t, "sub.example.com", Hostname("sub.example.com."))
	assert.Equal(t, "localhost", Hostname("localhost."))

	assert.Equal(t, "example.com", Hostname("example.com"))
	assert.Equal(t, "localhost", Hostname("localhost"))
	assert.Equal(t, "192.168.1.1", Hostname("192.168.1.1"))
	assert.Equal(t, "", Hostname(""))

	assert.Equal(t, "example.com.", Hostname("example.com.."))

	// Lowercases and decodes punycode to Unicode
	assert.Equal(t, "example.com", Hostname("EXAMPLE.COM"))
	assert.Equal(t, "münchen.de", Hostname("xn--mnchen-3ya.de"))
	assert.Equal(t, "münchen.de", Hostname("MÜNCHEN.DE."))

	// Folds Unicode confusables
	assert.Equal(t, "localhost", Hostname("ⓛocalhost"))

	// Falls back to lowercase when IDNA rejects the input, but NFKC still folds
	assert.Equal(t, "user_input.com", Hostname("User_Input.com"))
	assert.Equal(t, "localhost_x", Hostname("ⓛocalhost_x"))
}
