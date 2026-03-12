package pathtraversal

import (
	"path/filepath"
	"strings"
)

var linuxRootFolders = []string{
	"/bin/",
	"/boot/",
	"/dev/",
	"/etc/",
	"/home/",
	"/init/",
	"/lib/",
	"/media/",
	"/mnt/",
	"/opt/",
	"/proc/",
	"/root/",
	"/run/",
	"/sbin/",
	"/srv/",
	"/sys/",
	"/tmp/",
	"/usr/",
	"/var/",
	// Common container/cloud directories
	"/app/",
	"/code/",
	// macOS specific
	"/applications/",
	"/cores/",
	"/library/",
	"/private/",
	"/users/",
	"/system/",
	"/volumes/",
}

var dangerousPathStarts = append(linuxRootFolders, "c:/", "c:\\")

func startsWithUnsafePath(filePath, userInput string) bool {
	// Check if path is relative (not absolute or drive letter path)
	// Required because resolve will build absolute paths from relative paths
	if !filepath.IsAbs(filePath) || !filepath.IsAbs(userInput) {
		return false
	}

	normalizedPath := strings.ToLower(filepath.Clean(filePath))
	normalizedUserInput := strings.ToLower(filepath.Clean(userInput))

	for _, dangerousStart := range dangerousPathStarts {
		if strings.HasPrefix(normalizedPath, dangerousStart) &&
			strings.HasPrefix(normalizedPath, normalizedUserInput) {
			// If the user input is the same as the dangerous start, we don't want to flag it to prevent false positives
			// e.g. if user input is /etc/ and the path is /etc/passwd, we don't want to flag it, as long as the
			// user input does not contain a subdirectory or filename
			if userInput == dangerousStart || userInput == dangerousStart[:len(dangerousStart)-1] {
				return false
			}
			return true
		}
	}
	return false
}
