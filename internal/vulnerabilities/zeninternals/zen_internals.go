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
	"context"
	_ "embed"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

//go:embed libzen_internals.wasm
var wasmBin []byte

var (
	handle             unsafe.Pointer
	detectSQLInjection C.detect_sql_injection_func

	wasmRuntime  wazero.Runtime
	compiledWasm wazero.CompiledModule
	wasmPool     sync.Pool
)

type wasmInstance struct {
	mod       api.Module
	alloc     api.Function
	free      api.Function
	detectSQL api.Function
	memory    api.Memory
}

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

	// Compile WASM version
	wasmRuntime = wazero.NewRuntimeWithConfig(context.Background(), wazero.NewRuntimeConfigCompiler())
	var err error
	compiledWasm, err = wasmRuntime.CompileModule(context.Background(), wasmBin)
	if err != nil {
		log.Error(err)
	}

	wasmPool = sync.Pool{
		New: func() any {
			mod, err := wasmRuntime.InstantiateModule(context.Background(), compiledWasm, wazero.NewModuleConfig())
			if err != nil {
				panic(fmt.Sprintf("failed to instantiate module: %v", err))
			}
			return &wasmInstance{
				mod:       mod,
				alloc:     mod.ExportedFunction("wasm_alloc"),
				free:      mod.ExportedFunction("wasm_free"),
				detectSQL: mod.ExportedFunction("detect_sql_injection"),
				memory:    mod.Memory(),
			}
		},
	}

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

func DetectSQLInjectionWASM(query string, userInput string, dialect int) int {
	ctx := context.Background()

	inst := wasmPool.Get().(*wasmInstance)
	defer wasmPool.Put(inst)

	// Call the detection function
	result, err := callDetectSQL(ctx, inst.memory, inst.alloc, inst.free, inst.detectSQL, query, userInput, dialect)
	if err != nil {
		panic(err)
	}

	return int(result)
}

func callDetectSQL(
	ctx context.Context,
	memory api.Memory,
	alloc, free, detectSQL api.Function,
	query, userInput string,
	dialect int,
) (int32, error) {
	// Convert strings to bytes
	queryBytes := []byte(query)
	userInputBytes := []byte(userInput)

	// Allocate memory for query
	results, err := alloc.Call(ctx, uint64(len(queryBytes)))
	if err != nil {
		return 0, err
	}
	queryPtr := uint32(results[0])
	defer free.Call(ctx, uint64(queryPtr), uint64(len(queryBytes)))

	// Write query to WASM memory
	if !memory.Write(queryPtr, queryBytes) {
		return 0, fmt.Errorf("failed to write query to memory")
	}

	// Allocate memory for user input
	results, err = alloc.Call(ctx, uint64(len(userInputBytes)))
	if err != nil {
		return 0, err
	}
	userInputPtr := uint32(results[0])
	defer free.Call(ctx, uint64(userInputPtr), uint64(len(userInputBytes)))

	// Write user input to WASM memory
	if !memory.Write(userInputPtr, userInputBytes) {
		return 0, fmt.Errorf("failed to write user input to memory")
	}

	// Call detect_sql_injection(query_ptr, query_len, userinput_ptr, userinput_len, dialect)
	results, err = detectSQL.Call(ctx,
		uint64(queryPtr),
		uint64(len(queryBytes)),
		uint64(userInputPtr),
		uint64(len(userInputBytes)),
		uint64(dialect),
	)
	if err != nil {
		return 0, err
	}

	return int32(results[0]), nil
}
