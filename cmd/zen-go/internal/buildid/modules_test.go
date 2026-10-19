package buildid

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashModuleGraph(t *testing.T) {
	const original = `{"Path":"example.com/app","Dir":"/checkout/a","GoVersion":"1.25.0"}
{"Path":"example.com/dep","Version":"v1.0.0","Dir":"/cache/a","GoVersion":"1.24.0"}`
	before, err := hashModuleGraph([]byte(original))
	require.NoError(t, err)

	t.Run("order and machine paths do not matter", func(t *testing.T) {
		after, err := hashModuleGraph([]byte(`{"Path":"example.com/dep","Version":"v1.0.0","Dir":"/other/cache","GoVersion":"1.24.0"}
{"Path":"example.com/app","Dir":"/other/checkout","GoVersion":"1.25.0"}`))
		require.NoError(t, err)
		assert.Equal(t, before, after)
	})

	for name, data := range map[string]string{
		"version": `{"Path":"example.com/app","GoVersion":"1.25.0"}
{"Path":"example.com/dep","Version":"v1.1.0","GoVersion":"1.24.0"}`,
		"language version": `{"Path":"example.com/app","GoVersion":"1.26.0"}
{"Path":"example.com/dep","Version":"v1.0.0","GoVersion":"1.24.0"}`,
		"replacement": `{"Path":"example.com/app","GoVersion":"1.25.0"}
{"Path":"example.com/dep","Version":"v1.0.0","GoVersion":"1.24.0","Replace":{"Path":"example.com/fork","Version":"v1.0.0"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			after, err := hashModuleGraph([]byte(data))
			require.NoError(t, err)
			assert.NotEqual(t, before, after)
		})
	}
}

func TestHashModuleGraph_InvalidJSON(t *testing.T) {
	_, err := hashModuleGraph([]byte("invalid"))
	require.Error(t, err)
}
