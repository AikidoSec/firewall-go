package internal

import (
	"errors"
	"math"
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
	pid := os.Getpid()
	if pid < 0 || pid > math.MaxInt32 {
		return nil, errors.New("PID out of int32 range")
	}
	pid32 := int32(pid)
	proc, err := process.NewProcess(pid32)
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
// the build flags. Skips -a (would force unnecessary rebuilds).
func extractBuildFlags(args []string) []string {
	var result []string

	// Skip go binary and subcommand
	i := 1
	if i < len(args) && !strings.HasPrefix(args[i], "-") {
		i++
	}

	for ; i < len(args); i++ {
		arg := args[i]

		if arg == "--" {
			break
		}

		// Skip -a
		if arg == "-a" || arg == "--a" {
			continue
		}

		result = append(result, arg)
	}

	return result
}
