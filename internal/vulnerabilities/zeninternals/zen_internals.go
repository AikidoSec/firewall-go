package zeninternals

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

//go:embed libzen_internals.wasm
var wasmBin []byte

//go:embed libzen_internals.wasm.sha256sum
var checksumFile string

// compiledModule wraps a wazero.CompiledModule to allow atomic storage.
// This is needed because wazero.CompiledModule is an interface type,
// and atomic.Pointer requires a concrete type.
type compiledModule struct {
	module wazero.CompiledModule
}

var (
	interpreterRuntime wazero.Runtime
	compilerRuntime    wazero.Runtime
	compiledWasm       atomic.Pointer[compiledModule]
	wasmPool           sync.Pool
	compileOnce        sync.Once
	initOnce           sync.Once
)

// memoryWriter is a minimal interface for writing to memory.
// This allows for testability as wazero has unexported methods within api.Memory.
type memoryWriter interface {
	Write(offset uint32, data []byte) bool
}

// functionCaller is a minimal interface for calling functions.
// This allows for testability as wazero has unexported methods within api.Function.
type functionCaller interface {
	Call(ctx context.Context, params ...uint64) ([]uint64, error)
}

type wasmInstance struct {
	mod        api.Module
	alloc      api.Function
	free       api.Function
	detectSQL  api.Function
	memory     api.Memory
	isCompiled bool // Track if this instance uses the compiled module
}

// Init initializes the zen-internals library by verifying the WASM binary checksum,
// creating interpreter and compiler runtimes, and triggering async compilation.
// Instances can be created immediately using the interpreter runtime.
// This function is idempotent and safe to call multiple times.
func Init() error {
	var initErr error
	initOnce.Do(func() {
		err := verifySHA256()
		if err != nil {
			initErr = fmt.Errorf("failed to verify zen-internals: %w", err)
			return
		}

		// Create interpreter runtime for immediate use
		interpreterRuntime = wazero.NewRuntimeWithConfig(context.Background(), wazero.NewRuntimeConfig())

		// Create compiler runtime for compilation
		compilerRuntime = wazero.NewRuntimeWithConfig(context.Background(), wazero.NewRuntimeConfigCompiler())

		compileOnce.Do(func() {
			go compileModuleAsync()
		})

		wasmPool = sync.Pool{
			New: newWasmInstance,
		}

		log.Debug("Loaded zen-internals library, compilation in progress!")
	})

	return initErr
}

func compileModuleAsync() {
	ctx := context.Background()
	compiled, err := compilerRuntime.CompileModule(ctx, wasmBin)
	if err != nil {
		log.Error("Failed to compile zen-internals library",
			slog.Any("error", err))
		return
	}

	// Switch to compiled version
	compiledWasm.Store(&compiledModule{module: compiled})

	log.Debug("zen-internals compilation complete, now using compiled module!")
}

// hasCompileFinished returns whether the module has been compiled and is ready for use.
func hasCompileFinished() bool {
	return compiledWasm.Load() != nil
}

func newWasmInstance() any {
	var mod api.Module
	var err error

	// Check if compiled module is available
	compiled := compiledWasm.Load()
	usingCompiled := compiled != nil

	if compiled != nil {
		// Use compiled module with compiler runtime (faster)
		mod, err = compilerRuntime.InstantiateModule(context.Background(), compiled.module, wazero.NewModuleConfig())
	} else {
		// Use interpreter runtime with raw bytes (immediate availability)
		mod, err = interpreterRuntime.Instantiate(context.Background(), wasmBin)
	}

	if err != nil {
		log.Error("Failed to instantiate module", slog.Any("error", err))
		return nil
	}

	return &wasmInstance{
		mod:        mod,
		alloc:      mod.ExportedFunction("wasm_alloc"),
		free:       mod.ExportedFunction("wasm_free"),
		detectSQL:  mod.ExportedFunction("detect_sql_injection"),
		memory:     mod.Memory(),
		isCompiled: usingCompiled,
	}
}

// DetectSQLInjection performs SQL injection detection using the loaded library
func DetectSQLInjection(query string, userInput string, dialect int) int {
	ctx := context.Background()

	inst, ok := wasmPool.Get().(*wasmInstance)
	if !ok || inst == nil {
		log.Error("Failed to get WASM instance from pool")
		return 0
	}

	result, cleanupSucceeded, err := callDetectSQL(ctx,
		inst.memory,
		inst.alloc,
		inst.free,
		inst.detectSQL,
		query, userInput, dialect)
	if err != nil {
		log.Error("Failed to call detect_sql_injection", slog.Any("error", err))
		// Don't return instance to pool if there was an error

		// Close module to free memory before returning
		if closeErr := inst.mod.Close(ctx); closeErr != nil {
			log.Warn("Failed to close WASM module", slog.Any("error", closeErr))
		}
		return 0
	}

	// Return instance to pool if cleanup succeeded AND:
	// - Instance is compiled, OR
	// - Compilation hasn't completed yet (still need to reuse interpreter instances)
	// Once compilation completes, only compiled instances go back to pool
	shouldPool := cleanupSucceeded && (inst.isCompiled || !hasCompileFinished())

	if shouldPool {
		wasmPool.Put(inst)
	} else {
		// Close module to free memory if not returning to pool
		if closeErr := inst.mod.Close(ctx); closeErr != nil {
			log.Warn("Failed to close WASM module", slog.Any("error", closeErr))
		}
	}

	return int(result)
}

// callDetectSQL performs SQL injection detection with safe memory management.
// Handles string allocation, pointer validation, and cleanup to safely interface
// with the underlying detection library. Returns the result (1 if SQL injection detected,
// 0 otherwise), a boolean indicating if cleanup succeeded, or error if allocation/call fails.
func callDetectSQL(
	ctx context.Context,
	memory memoryWriter,
	alloc, free, detectSQL functionCaller,
	query, userInput string,
	dialect int,
) (int32, bool, error) {
	if dialect < 0 || dialect > int(SQLite) {
		return 0, false, fmt.Errorf("invalid dialect: %d, must be between 0 and %d", dialect, int(SQLite))
	}

	// Convert strings to bytes
	queryBytes := []byte(query)
	userInputBytes := []byte(userInput)

	// Track if cleanup succeeds
	cleanupSucceeded := true

	// Allocate and write query to WASM memory
	queryPtr, queryLen, freeQuery, err := allocateAndWriteString(ctx, memory, alloc, free, queryBytes, "query")
	if err != nil {
		return 0, false, err
	}
	defer func() {
		if !freeQuery() {
			cleanupSucceeded = false
		}
	}()

	// Allocate and write user input to WASM memory
	userInputPtr, userInputLen, freeUserInput, err := allocateAndWriteString(ctx, memory, alloc, free, userInputBytes, "user input")
	if err != nil {
		return 0, false, err
	}
	defer func() {
		if !freeUserInput() {
			cleanupSucceeded = false
		}
	}()

	// Call detect_sql_injection(query_ptr, query_len, userinput_ptr, userinput_len, dialect)
	results, err := detectSQL.Call(ctx,
		uint64(queryPtr),
		queryLen,
		uint64(userInputPtr),
		userInputLen,
		uint64(dialect),
	)
	if err != nil {
		return 0, false, fmt.Errorf("failed to call detect_sql_injection: %w", err)
	}
	if len(results) == 0 {
		return 0, false, fmt.Errorf("detect_sql_injection returned no results")
	}

	// Safely convert result to int32, checking for overflow
	result := results[0]
	if result > uint64(math.MaxInt32) {
		return 0, false, fmt.Errorf("detect_sql_injection returned value too large: %d", result)
	}
	return int32(result), cleanupSucceeded, nil
}

// allocateAndWriteString allocates memory for a string, writes it to WASM memory, and returns the pointer and length
// The caller is responsible for freeing the memory using the returned free function
// The cleanup function returns true if freeing succeeded, false otherwise
func allocateAndWriteString(ctx context.Context, memory memoryWriter, alloc, free functionCaller, data []byte, name string) (uint32, uint64, func() bool, error) {
	// Check for potential overflow in string length
	const maxStringLen = 1 << 30 // 1GB limit to prevent overflow
	if len(data) > maxStringLen {
		return 0, 0, nil, fmt.Errorf("%s too large: %d bytes, maximum allowed: %d", name, len(data), maxStringLen)
	}

	// Allocate memory
	dataLen := uint64(len(data))
	results, err := alloc.Call(ctx, dataLen)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("failed to allocate memory for %s: %w", name, err)
	}
	if len(results) == 0 {
		return 0, 0, nil, fmt.Errorf("allocation failed for %s: no results returned", name)
	}

	// Safely convert pointer to uint32, checking for overflow
	ptrRaw := results[0]
	if ptrRaw > uint64(^uint32(0)) {
		return 0, 0, nil, fmt.Errorf("%s pointer too large: %d", name, ptrRaw)
	}
	ptr := uint32(ptrRaw)

	// Write data to WASM memory
	if !memory.Write(ptr, data) {
		return 0, 0, nil, fmt.Errorf("failed to write %s to memory", name)
	}

	// Create cleanup function to free the mmemory we manually allocated in WASM
	// Returns true if freeing succeeded, false otherwise
	cleanup := func() bool {
		if _, freeErr := free.Call(ctx, uint64(ptr), dataLen); freeErr != nil {
			// Log error but don't fail the main operation
			log.Warn("Failed to free memory", slog.String("name", name), slog.Any("error", freeErr))
			return false
		}
		return true
	}

	return ptr, dataLen, cleanup, nil
}

func verifySHA256() error {
	parts := strings.Fields(checksumFile)
	if len(parts) < 2 {
		return fmt.Errorf("invalid checksum file format")
	}

	expectedHash := parts[0]

	hash := sha256.Sum256(wasmBin)
	actualHash := hex.EncodeToString(hash[:])

	if actualHash != expectedHash {
		return fmt.Errorf("sha256 mismatch: expected %s, got %s", expectedHash, actualHash)
	}

	return nil
}
