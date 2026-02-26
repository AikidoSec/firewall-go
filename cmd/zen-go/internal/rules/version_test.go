package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckMinVersions_Satisfied(t *testing.T) {
	entries := []MinVersionEntry{
		{File: "sinks/sql/zen.instrument.yml", Version: "0.2.0"},
	}
	require.NoError(t, CheckMinVersions(entries, "0.2.0"))
	require.NoError(t, CheckMinVersions(entries, "0.3.0"))
	require.NoError(t, CheckMinVersions(entries, "1.0.0"))
}

func TestCheckMinVersions_NotMet(t *testing.T) {
	entries := []MinVersionEntry{
		{File: "sinks/sql/zen.instrument.yml", Version: "0.3.0"},
	}
	err := CheckMinVersions(entries, "0.2.0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires zen-go >= v0.3.0")
	assert.Contains(t, err.Error(), "current version is v0.2.0")
	assert.Contains(t, err.Error(), "please upgrade")
}

func TestCheckMinVersions_Empty(t *testing.T) {
	require.NoError(t, CheckMinVersions(nil, "0.1.0"))
	require.NoError(t, CheckMinVersions([]MinVersionEntry{}, "0.1.0"))
}

func TestCheckMinVersions_MultipleEntries(t *testing.T) {
	entries := []MinVersionEntry{
		{File: "a.yml", Version: "0.1.0"},
		{File: "b.yml", Version: "0.3.0"},
	}
	require.NoError(t, CheckMinVersions(entries, "0.3.0"))

	err := CheckMinVersions(entries, "0.2.0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "b.yml")
}

func TestCheckMinVersions_InvalidCurrentVersion(t *testing.T) {
	entries := []MinVersionEntry{
		{File: "a.yml", Version: "0.1.0"},
	}
	err := CheckMinVersions(entries, "bad")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse current version")
}

func TestCheckMinVersions_InvalidMinVersion(t *testing.T) {
	entries := []MinVersionEntry{
		{File: "a.yml", Version: "not-a-version"},
	}
	err := CheckMinVersions(entries, "0.1.0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse min-zen-go-version")
}

func TestCheckMinVersions_VPrefix(t *testing.T) {
	entries := []MinVersionEntry{
		{File: "a.yml", Version: "0.2.0"},
	}
	require.NoError(t, CheckMinVersions(entries, "v0.2.0"))
}

func TestParseSemver(t *testing.T) {
	v, err := parseSemver("1.2.3")
	require.NoError(t, err)
	assert.Equal(t, semver{1, 2, 3}, v)

	v, err = parseSemver("v0.3.0")
	require.NoError(t, err)
	assert.Equal(t, semver{0, 3, 0}, v)

	_, err = parseSemver("1.2")
	assert.Error(t, err)

	_, err = parseSemver("abc")
	assert.Error(t, err)
}

func TestShortPath(t *testing.T) {
	assert.Equal(t, "sinks/sql/zen.instrument.yml",
		shortPath("/home/user/.cache/go/mod/github.com/!aikido!sec/firewall-go@v0.3.0/instrumentation/sinks/sql/zen.instrument.yml"))
	assert.Equal(t, "sources/gin/zen.instrument.yml",
		shortPath("/tmp/instrumentation/sources/gin/zen.instrument.yml"))
	assert.Equal(t, "no-marker.yml", shortPath("no-marker.yml"))
}

func TestCompareSemver(t *testing.T) {
	assert.Equal(t, 0, compareSemver(semver{1, 2, 3}, semver{1, 2, 3}))
	assert.Equal(t, -1, compareSemver(semver{0, 2, 0}, semver{0, 3, 0}))
	assert.Equal(t, 1, compareSemver(semver{1, 0, 0}, semver{0, 9, 9}))
	assert.Equal(t, -1, compareSemver(semver{0, 2, 0}, semver{0, 2, 1}))
	assert.Equal(t, 1, compareSemver(semver{0, 2, 1}, semver{0, 2, 0}))
}
