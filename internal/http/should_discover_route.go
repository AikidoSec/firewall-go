package http

import (
	"path/filepath"
	"strings"
)

var excludedMethods = []string{"OPTIONS", "HEAD"}
var ignoreExtensions = []string{"properties", "asp", "aspx", "jsp", "config"}
var allowExtensions = []string{"html", "php"}
var ignoreStrings = []string{"cgi-bin"}

func shouldDiscoverRoute(statusCode int, route, method string) bool {
	if containsStr(excludedMethods, method) {
		return false
	}

	if statusCode < 200 || statusCode > 399 {
		return false
	}

	segments := strings.Split(route, "/")

	// e.g. /path/to/.file or /.directory/file
	for _, segment := range segments {
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

		if containsStr(allowExtensions, extension) {
			return true
		}

		if len(extension) >= 2 && len(extension) <= 5 {
			return false
		}

		if containsStr(ignoreExtensions, extension) {
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

func containsStr(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
