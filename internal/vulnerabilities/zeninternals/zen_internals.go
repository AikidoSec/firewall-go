package zeninternals

// #cgo LDFLAGS: -ldl
// #include <dlfcn.h>
// #include <stdlib.h>
//
// typedef int (*detect_sql_injection_func)(const char*, size_t, const char*, size_t, int);
//
// int call_detect_sql_injection(detect_sql_injection_func func, const char* query, size_t query_len, const char* input, size_t input_len, int sql_dialect) {
//     return func(query, query_len, input, input_len, sql_dialect);
// }
import "C"

import (
	"fmt"
	"log/slog"
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
		log.Error("Failed to load zen-internals library",
			slog.String("path", C.GoString(zenInternalsLibPath)),
			slog.String("error", C.GoString(C.dlerror())))
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
	log.Debug("Loaded zen-internals library!")
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

	queryLen := C.size_t(len(query))
	userInputLen := C.size_t(len(userInput))

	// Call the detect_sql_injection function
	result := int(C.call_detect_sql_injection(detectSQLInjection, cQuery, queryLen, cUserInput, userInputLen, C.int(dialect)))
	log.Debug("DetectSqlInjection",
		slog.String("query", query),
		slog.String("userInput", userInput),
		slog.Int("dialect", dialect),
		slog.Int("result", result))
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
