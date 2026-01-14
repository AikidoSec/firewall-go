package internal

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/shirou/gopsutil/v4/process"
)

var (
	inheritedFlags     []string
	inheritedFlagsErr  error
	inheritedFlagsOnce sync.Once
)

// parentBuildFlags returns build flags from the parent go command.
// This ensures packages.Load uses the same build configuration,
// preventing cache misses and fingerprint errors.
func parentBuildFlags() ([]string, error) {
	inheritedFlagsOnce.Do(func() {
		inheritedFlags, inheritedFlagsErr = captureParentFlags()
	})
	return inheritedFlags, inheritedFlagsErr
}

func captureParentFlags() ([]string, error) {
	goBinary, err := locateGoBinary()
	if err != nil {
		return nil, err
	}

	args, err := findParentGoProcess(goBinary)
	if err != nil {
		return nil, err
	}

	return extractBuildFlags(args), nil
}

func locateGoBinary() (string, error) {
	path, err := exec.LookPath("go")
	if err != nil {
		return "", err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(path)
}

func findParentGoProcess(goBinary string) ([]string, error) {
	proc, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		return nil, err
	}

	for {
		proc, err = proc.Parent()
		if err != nil {
			return nil, err
		}

		args, err := proc.CmdlineSlice()
		if err != nil || len(args) == 0 {
			continue
		}

		if matchesGoBinary(args[0], goBinary) {
			return args, nil
		}
	}
}

func matchesGoBinary(candidate, goBinary string) bool {
	resolved, err := exec.LookPath(candidate)
	if err != nil {
		return false
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return false
	}
	resolved, err = filepath.EvalSymlinks(resolved)
	if err != nil {
		return false
	}
	return resolved == goBinary
}

// extractBuildFlags parses the parent go command's arguments and returns
// the build flags. Skips -a (would force unnecessary rebuilds) and
// -toolexec (we add our own).
func extractBuildFlags(args []string) []string {
	standalone := map[string]bool{
		"-asan":       true,
		"-cover":      true,
		"-linkshared": true,
		"-modcacherw": true,
		"-msan":       true,
		"-race":       true,
		"-trimpath":   true,
		"-work":       true,
	}
	withValue := map[string]bool{
		"-asmflags":   true,
		"-buildmode":  true,
		"-buildvcs":   true,
		"-compiler":   true,
		"-covermode":  true,
		"-coverpkg":   true,
		"-gccgoflags": true,
		"-gcflags":    true,
		"-ldflags":    true,
		"-mod":        true,
		"-modfile":    true,
		"-overlay":    true,
		"-pgo":        true,
		"-pkgdir":     true,
		"-tags":       true,
	}

	var result []string

	// Skip go binary and subcommand
	i := 1
	if i < len(args) && !strings.HasPrefix(args[i], "-") {
		i++
	}

	for ; i < len(args); i++ {
		arg := args[i]
		if arg == "--" || !strings.HasPrefix(arg, "-") {
			break
		}

		if strings.Contains(arg, "=") {
			if extracted := extractFlag(arg, "", standalone, withValue); extracted != "" {
				result = append(result, extracted)
			}
			continue
		}

		nextVal := ""
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			nextVal = args[i+1]
		}
		if extracted := extractFlag(arg, nextVal, standalone, withValue); extracted != "" {
			result = append(result, extracted)
			if nextVal != "" && withValue[strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-")] {
				i++
			}
		}
	}

	return result
}

func extractFlag(flag, nextArg string, standalone, withValue map[string]bool) string {
	// Normalize -- to -
	normalized := strings.TrimPrefix(flag, "-")
	normalized = "-" + normalized

	if key, val, ok := strings.Cut(normalized, "="); ok {
		name := strings.TrimPrefix(key, "-")
		if withValue[name] {
			return key + "=" + val
		}
		return ""
	}

	name := strings.TrimPrefix(normalized, "-")
	if standalone[name] {
		return normalized
	}
	if withValue[name] && nextArg != "" {
		return normalized + "=" + nextArg
	}
	return ""
}
