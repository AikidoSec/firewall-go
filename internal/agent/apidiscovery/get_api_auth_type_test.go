package apidiscovery

import (
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/stretchr/testify/assert"
)

// Test for detecting authorization header
func TestDetectAuthorizationHeader(t *testing.T) {
	assert := assert.New(t)

	headers := map[string][]string{
		"authorization": {"Bearer token"},
	}
	cookies := map[string]string{}
	assert.Equal([]*aikido_types.APIAuthType{
		{Type: "http", Scheme: "bearer"},
	}, GetApiAuthType(headers, cookies))

	headers = map[string][]string{
		"authorization": {"Basic base64"},
	}
	assert.Equal([]*aikido_types.APIAuthType{
		{Type: "http", Scheme: "basic"},
	}, GetApiAuthType(headers, cookies))

	headers = map[string][]string{
		"authorization": {"custom"},
	}
	assert.Equal([]*aikido_types.APIAuthType{
		{Type: "apiKey", In: "header", Name: "Authorization"},
	}, GetApiAuthType(headers, cookies))
}

// Test for detecting API keys
func TestDetectApiKeys(t *testing.T) {
	assert := assert.New(t)

	headers := map[string][]string{
		"x_api_key": {"token"},
	}
	cookies := map[string]string{}
	assert.Equal([]*aikido_types.APIAuthType{
		{Type: "apiKey", In: ("header"), Name: ("x-api-key")},
	}, GetApiAuthType(headers, cookies))

	headers = map[string][]string{
		"api_key": {"token"},
	}
	assert.Equal([]*aikido_types.APIAuthType{
		{Type: "apiKey", In: ("header"), Name: ("api-key")},
	}, GetApiAuthType(headers, cookies))
}

// Test for detecting auth cookies
func TestDetectAuthCookies(t *testing.T) {
	assert := assert.New(t)

	headers := map[string][]string{}
	cookies := map[string]string{
		"api-key": "token",
	}

	assert.Equal([]*aikido_types.APIAuthType{
		{Type: "apiKey", In: ("cookie"), Name: ("api-key")},
	}, GetApiAuthType(headers, cookies))

	cookies = map[string]string{
		"session": "test",
	}
	assert.Equal([]*aikido_types.APIAuthType{
		{Type: "apiKey", In: ("cookie"), Name: ("session")},
	}, GetApiAuthType(headers, cookies))
}

// Test for no authentication
func TestNoAuth(t *testing.T) {
	assert := assert.New(t)

	headers := map[string][]string{}
	cookies := map[string]string{}

	assert.Empty(GetApiAuthType(headers, cookies))

	headers = map[string][]string{
		"authorization": {},
	}
	assert.Empty(GetApiAuthType(headers, cookies))

	headers = map[string][]string{
		"authorization": {""},
	}
	assert.Empty(GetApiAuthType(headers, cookies))
}
