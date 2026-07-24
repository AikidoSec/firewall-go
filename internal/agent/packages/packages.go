package packages

import (
	"runtime/debug"

	"github.com/AikidoSec/firewall-go/internal/agent/aikido_types"
	"github.com/AikidoSec/firewall-go/internal/agent/utils"
)

func Get() []aikido_types.PackageInfo {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return []aikido_types.PackageInfo{}
	}

	packages := fromBuildInfo(info)

	return packages
}

func fromBuildInfo(info *debug.BuildInfo) []aikido_types.PackageInfo {
	packages := make([]aikido_types.PackageInfo, 0, len(info.Deps))
	requiredAt := utils.GetTime()

	for _, dep := range info.Deps {
		mod := dep
		if dep.Replace != nil {
			mod = dep.Replace
		}
		packages = append(packages, aikido_types.PackageInfo{
			Name:       mod.Path,
			Version:    mod.Version,
			RequiredAt: requiredAt,
		})
	}

	return packages
}
