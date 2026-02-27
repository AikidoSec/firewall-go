package http

import (
	"path/filepath"
	"slices"
	"strings"
)

var (
	excludedMethods  = []string{"OPTIONS", "HEAD"}
	ignoreExtensions = []string{"properties", "asp", "aspx", "jsp", "config"}
	allowExtensions  = []string{"html", "php"}
	ignoreStrings    = []string{"cgi-bin"}
)

func shouldDiscoverRoute(statusCode int, route, method string) bool {
	if slices.Contains(excludedMethods, method) {
		return false
	}

	if statusCode < 200 || statusCode > 399 {
		return false
	}

	segments := strings.SplitSeq(route, "/")

	// e.g. /path/to/.file or /.directory/file
	for segment := range segments {
		if isDotFile(segment) {
			return false
		}

		if containsIgnoredString(segment) {
			return false
		}

		if !isAllowedExtension(segment) {
			return false
		}
	}

	return true
}

func isAllowedExtension(segment string) bool {
	extension := filepath.Ext(segment)

	if extension != "" && strings.HasPrefix(extension, ".") {
		extension = extension[1:]

		if slices.Contains(allowExtensions, extension) {
			return true
		}

		if len(extension) >= 2 && len(extension) <= 5 {
			return false
		}

		if slices.Contains(ignoreExtensions, extension) {
			return false
		}
	}

	return true
}

func isDotFile(segment string) bool {
	if segment == ".well-known" {
		return false
	}

	return strings.HasPrefix(segment, ".") && len(segment) > 1
}

func containsIgnoredString(segment string) bool {
	for _, str := range ignoreStrings {
		if strings.Contains(segment, str) {
			return true
		}
	}
	return false
}
