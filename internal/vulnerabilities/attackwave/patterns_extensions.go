package attackwave

import "strings"

// suspiciousExtensions contains file extensions commonly targeted by web scanners
var suspiciousExtensions map[string]bool

func init() {
	extensions := []string{
		"env",
		"bak",
		"sql",
		"sqlite",
		"sqlite3",
		"db",
		"old",
		"save",
		"orig",
		"sqlitedb",
		"sqlite3db",
	}

	suspiciousExtensions = make(map[string]bool, len(extensions))
	for _, extension := range extensions {
		suspiciousExtensions[strings.ToLower(extension)] = true
	}
}
