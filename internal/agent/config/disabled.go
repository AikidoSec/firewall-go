package config

import "sync/atomic"

var isZenDisabled atomic.Bool

func SetZenDisabled(disabled bool) {
	isZenDisabled.Store(disabled)
}

func IsZenDisabled() bool {
	return isZenDisabled.Load()
}
