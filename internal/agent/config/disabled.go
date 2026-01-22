package config

import "sync/atomic"

var isZenDisabled atomic.Bool
var isZenLoaded atomic.Bool

func SetZenDisabled(disabled bool) {
	isZenDisabled.Store(disabled)
}

func IsZenDisabled() bool {
	return isZenDisabled.Load()
}

func SetZenLoaded(loaded bool) {
	isZenLoaded.Store(loaded)
}

func IsZenLoaded() bool {
	return isZenLoaded.Load()
}

// ShouldProtect returns true if protection should run.
// Protection runs when zen is not disabled AND has been loaded successfully.
func ShouldProtect() bool {
	return !IsZenDisabled() && IsZenLoaded()
}
