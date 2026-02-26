package rules

import (
	"cmp"
	"fmt"
	"strconv"
	"strings"
)

// CheckMinVersions checks that currentVersion satisfies all minimum version requirements.
// Returns an error listing the first unsatisfied requirement.
func CheckMinVersions(minVersions []MinVersionEntry, currentVersion string) error {
	cur, err := parseSemver(currentVersion)
	if err != nil {
		return fmt.Errorf("zen-go: failed to parse current version %q: %w", currentVersion, err)
	}

	for _, entry := range minVersions {
		required, err := parseSemver(entry.Version)
		if err != nil {
			return fmt.Errorf("zen-go: failed to parse min-zen-go-version %q in %s: %w", entry.Version, entry.File, err)
		}

		if compareSemver(cur, required) < 0 {
			return fmt.Errorf("zen-go: %s requires zen-go >= v%s, but current version is v%s — please upgrade zen-go",
				shortPath(entry.File), strings.TrimPrefix(entry.Version, "v"), strings.TrimPrefix(currentVersion, "v"))
		}
	}

	return nil
}

// shortPath trims an absolute file path to the portion after "instrumentation/",
// e.g. "/home/user/.cache/go/mod/.../instrumentation/sinks/sql/zen.instrument.yml"
// becomes "sinks/sql/zen.instrument.yml". If the marker is not found, returns the
// original path.
func shortPath(path string) string {
	const marker = "instrumentation/"
	if i := strings.LastIndex(path, marker); i != -1 {
		return path[i+len(marker):]
	}
	return path
}

type semver struct {
	major, minor, patch int
}

func parseSemver(s string) (semver, error) {
	raw := strings.TrimPrefix(s, "v")
	parts := strings.SplitN(raw, ".", 3)
	if len(parts) != 3 {
		return semver{}, fmt.Errorf("expected format major.minor.patch, got %q", s)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return semver{}, fmt.Errorf("invalid major version: %w", err)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return semver{}, fmt.Errorf("invalid minor version: %w", err)
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return semver{}, fmt.Errorf("invalid patch version: %w", err)
	}

	return semver{major, minor, patch}, nil
}

func compareSemver(a, b semver) int {
	if c := cmp.Compare(a.major, b.major); c != 0 {
		return c
	}
	if c := cmp.Compare(a.minor, b.minor); c != 0 {
		return c
	}
	return cmp.Compare(a.patch, b.patch)
}
