package zeninternals

// #cgo LDFLAGS: -ldl
// #include <dlfcn.h>
// #include <stdlib.h>
//
// typedef int (*detect_sql_injection_func)(const char*, const char*, int);
//
// int call_detect_sql_injection(detect_sql_injection_func func, const char* query, const char* input, int sql_dialect) {
//     return func(query, input, sql_dialect);
// }
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/AikidoSec/firewall-go/internal/log"
)

var (
	handle             unsafe.Pointer
	detectSQLInjection C.detect_sql_injection_func
)

func Init() bool {
	zenInternalsLibPath := C.CString(fmt.Sprintf(
		"/opt/aikido/lib/libzen_internals_%s-unknown-linux-gnu.so",
		getArch(),
	))
	defer C.free(unsafe.Pointer(zenInternalsLibPath))

	handle := C.dlopen(zenInternalsLibPath, C.RTLD_LAZY)
	if handle == nil {
		log.Errorf("Failed to load zen-internals library from '%s' with error %s!", C.GoString(zenInternalsLibPath), C.GoString(C.dlerror()))
		return false
	}

	detectSQLInjectionFnName := C.CString("detect_sql_injection")
	defer C.free(unsafe.Pointer(detectSQLInjectionFnName))

	vDetectSQLInjection := C.dlsym(handle, detectSQLInjectionFnName)
	if vDetectSQLInjection == nil {
		log.Error("Failed to load detect_sql_injection function from zen-internals library!")
		return false
	}

	detectSQLInjection = (C.detect_sql_injection_func)(vDetectSQLInjection)
	log.Debugf("Loaded zen-internals library!")
	return true
}

func Uninit() {
	detectSQLInjection = nil

	if handle != nil {
		C.dlclose(handle)
		handle = nil
	}
}

// DetectSQLInjection performs SQL injection detection using the loaded library
func DetectSQLInjection(query string, userInput string, dialect int) int {
	if detectSQLInjection == nil {
		return 0
	}

	// Convert strings to C strings
	cQuery := C.CString(query)
	cUserInput := C.CString(userInput)
	defer C.free(unsafe.Pointer(cQuery))
	defer C.free(unsafe.Pointer(cUserInput))

	// Call the detect_sql_injection function
	result := int(C.call_detect_sql_injection(detectSQLInjection, cQuery, cUserInput, C.int(dialect)))
	log.Debugf("DetectSqlInjection(%s, %s, %d) -> %d", query, userInput, dialect, result)
	return result
}

func getArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	}
	panic(fmt.Sprintf("Running on unsupported architecture \"%s\"!", runtime.GOARCH))
}
