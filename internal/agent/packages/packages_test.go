package packages

import (
	"runtime/debug"
	"testing"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/stretchr/testify/assert"
)

func TestFromBuildInfo(t *testing.T) {
	t.Run("collects module name and version", func(t *testing.T) {
		info := &debug.BuildInfo{
			Deps: []*debug.Module{
				{Path: "github.com/foo/bar", Version: "v1.2.3"},
			},
		}

		packages := fromBuildInfo(info)

		assert.Len(t, packages, 1)
		assert.Equal(t, "github.com/foo/bar", packages[0].Name)
		assert.Equal(t, "v1.2.3", packages[0].Version)
		assert.NotZero(t, packages[0].RequiredAt)
	})

	t.Run("uses the replacement module when present", func(t *testing.T) {
		info := &debug.BuildInfo{
			Deps: []*debug.Module{
				{
					Path:    "github.com/foo/bar",
					Version: "v1.2.3",
					Replace: &debug.Module{Path: "github.com/foo/bar", Version: "v1.2.4"},
				},
			},
		}

		packages := fromBuildInfo(info)

		assert.Len(t, packages, 1)
		assert.Equal(t, "v1.2.4", packages[0].Version)
	})

	t.Run("no deps returns an empty slice", func(t *testing.T) {
		packages := fromBuildInfo(&debug.BuildInfo{})

		assert.NotNil(t, packages)
		assert.Empty(t, packages)
	})
}

func TestGet(t *testing.T) {
	packages := Get()

	assert.NotNil(t, packages)
	assert.IsType(t, []aikido_types.PackageInfo{}, packages)
}
