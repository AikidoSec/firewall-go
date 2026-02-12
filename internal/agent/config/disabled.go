package config

import (
	"sync"
	"sync/atomic"

	"github.com/AikidoSec/firewall-go/internal/log"
)

// compiledWithZenGo is set to "true" at link time by zen-go toolexec via -ldflags -X.
// When empty, the binary was not compiled with zen-go and instrumentation is inactive.
var compiledWithZenGo string

var (
	isZenDisabled atomic.Bool
	isZenLoaded   atomic.Bool
	warnOnce      sync.Once
)

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

// WarnIfNotProtected logs a warning once if zen.Protect() has not been called
// and Zen is not explicitly disabled. This helps customers notice when they
// have configured the middleware but forgotten to call zen.Protect().
func WarnIfNotProtected() {
	if IsZenLoaded() || IsZenDisabled() {
		return
	}
	warnOnce.Do(func() {
		log.Warn("Aikido middleware is active but zen.Protect() was not called. Requests will not be protected.")
	})
}

// IsCompiledWithZenGo returns true if the binary was compiled with zen-go toolexec.
func IsCompiledWithZenGo() bool {
	return compiledWithZenGo == "true"
}

// ResetWarnOnce resets the WarnIfNotProtected once guard.
func ResetWarnOnce() {
	warnOnce = sync.Once{}
}
