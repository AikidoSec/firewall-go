package config

import "runtime/debug"

const fallbackVersion = "1.2.14"

var Version = resolveVersion()

func resolveVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return fallbackVersion
	}

	return versionFromBuildInfo(info)
}

func versionFromBuildInfo(info *debug.BuildInfo) string {
	const modulePath = "github.com/AikidoSec/firewall-go"

	if info.Main.Path == modulePath {
		return moduleVersion(info.Main)
	}

	for _, dep := range info.Deps {
		if dep.Path == modulePath {
			return moduleVersion(*dep)
		}
	}

	return fallbackVersion
}

func moduleVersion(mod debug.Module) string {
	effectiveModule := mod
	if mod.Replace != nil {
		effectiveModule = *mod.Replace
	}
	if effectiveModule.Version == "" || effectiveModule.Version == "(devel)" {
		return fallbackVersion
	}
	return effectiveModule.Version
}
