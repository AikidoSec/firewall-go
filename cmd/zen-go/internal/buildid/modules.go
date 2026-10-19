package buildid

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"strings"
)

// Ignore machine-specific directories and local replacement source contents.
type moduleIdentity struct {
	Path      string
	Version   string
	GoVersion string
	Replace   *moduleIdentity `json:",omitempty"`
}

// ComputeModuleGraphHash tracks dependency versions for imports we inject after
// Go computes its cache keys. Query only module metadata to avoid recursive builds.
func ComputeModuleGraphHash(moduleFlags []string) (string, error) {
	args := append([]string{"list", "-m", "-json"}, moduleFlags...)
	args = append(args, "all")
	cmd := exec.Command("go", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("resolving module graph: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return hashModuleGraph(output)
}

func hashModuleGraph(data []byte) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var modules []moduleIdentity
	for {
		var mod moduleIdentity
		if err := decoder.Decode(&mod); err != nil {
			if err == io.EOF {
				break
			}
			return "", fmt.Errorf("decoding module graph: %w", err)
		}
		modules = append(modules, mod)
	}
	slices.SortFunc(modules, func(a, b moduleIdentity) int {
		return strings.Compare(a.Path, b.Path)
	})
	h := sha256.New()
	if err := json.NewEncoder(h).Encode(modules); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(h.Sum(nil))[:16], nil
}

func ComputeToolHash(instrumentationHash, moduleGraphHash string) string {
	sum := sha256.Sum256([]byte(instrumentationHash + "\n" + moduleGraphHash))
	return base64.URLEncoding.EncodeToString(sum[:])[:16]
}
