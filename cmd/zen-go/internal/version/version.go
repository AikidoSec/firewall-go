package version

import (
	"runtime/debug"
	"strings"
)

func Resolve(fallback string) string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return fallback
	}

	return resolveFromBuildInfo(bi, fallback)
}

func resolveFromBuildInfo(bi *debug.BuildInfo, fallback string) string {
	if bi.Main.Version == "" || bi.Main.Version == "(devel)" {
		return fallback
	}

	return strings.TrimPrefix(bi.Main.Version, "v")
}
