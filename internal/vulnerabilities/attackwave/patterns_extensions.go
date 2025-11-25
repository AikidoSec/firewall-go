package attackwave

// suspiciousExtensions contains file extensions commonly targeted by web scanners
var suspiciousExtensions = map[string]bool{
	"env":       true,
	"bak":       true,
	"sql":       true,
	"sqlite":    true,
	"sqlite3":   true,
	"db":        true,
	"old":       true,
	"save":      true,
	"orig":      true,
	"sqlitedb":  true,
	"sqlite3db": true,
}
