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

	"github.com/AikidoSec/firewall-go/internal/log"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

//go:embed libzen_internals.wasm
var wasmBin []byte

//go:embed libzen_internals.wasm.sha256sum
var checksumFile string

var (
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

func Init() error {
	err := verifySHA256()
	if err != nil {
		return fmt.Errorf("failed to verify zen-internals: %w", err)
	}

	wasmRuntime = wazero.NewRuntimeWithConfig(context.Background(), wazero.NewRuntimeConfigCompiler())

	compiledWasm, err = wasmRuntime.CompileModule(context.Background(), wasmBin)
	if err != nil {
		log.Error("Failed to load zen-internals library",
			slog.Any("error", err))
		return fmt.Errorf("failed to load zen-internals library: %w", err)
	}

	wasmPool = sync.Pool{
		New: newWasmInstance,
	}

	log.Debug("Loaded zen-internals library!")

	return nil
}

func newWasmInstance() any {
	mod, err := wasmRuntime.InstantiateModule(context.Background(), compiledWasm, wazero.NewModuleConfig())
	if err != nil {
		log.Error("Failed to instantiate module", slog.Any("error", err))
		return nil
	}

	return &wasmInstance{
		mod:       mod,
		alloc:     mod.ExportedFunction("wasm_alloc"),
		free:      mod.ExportedFunction("wasm_free"),
		detectSQL: mod.ExportedFunction("detect_sql_injection"),
		memory:    mod.Memory(),
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
	defer wasmPool.Put(inst)

	result, err := callDetectSQL(ctx, inst.memory, inst.alloc, inst.free, inst.detectSQL, query, userInput, dialect)
	if err != nil {
		log.Error("Failed to call detect_sql_injection", slog.Any("error", err))
		return 0
	}

	return int(result)
}

// callDetectSQL performs SQL injection detection with safe memory management.
// Handles string allocation, pointer validation, and cleanup to safely interface
// with the underlying detection library. Returns 1 if SQL injection detected,
// 0 otherwise, or error if allocation/call fails.
func callDetectSQL(
	ctx context.Context,
	memory api.Memory,
	alloc, free, detectSQL api.Function,
	query, userInput string,
	dialect int,
) (int32, error) {
	if dialect < 0 || dialect > int(SQLite) {
		return 0, fmt.Errorf("invalid dialect: %d, must be between 0 and %d", dialect, int(SQLite))
	}

	// Convert strings to bytes
	queryBytes := []byte(query)
	userInputBytes := []byte(userInput)

	// Allocate and write query to WASM memory
	queryPtr, queryLen, freeQuery, err := allocateAndWriteString(ctx, memory, alloc, free, queryBytes, "query")
	if err != nil {
		return 0, err
	}
	defer freeQuery()

	// Allocate and write user input to WASM memory
	userInputPtr, userInputLen, freeUserInput, err := allocateAndWriteString(ctx, memory, alloc, free, userInputBytes, "user input")
	if err != nil {
		return 0, err
	}
	defer freeUserInput()

	// Call detect_sql_injection(query_ptr, query_len, userinput_ptr, userinput_len, dialect)
	results, err := detectSQL.Call(ctx,
		uint64(queryPtr),
		queryLen,
		uint64(userInputPtr),
		userInputLen,
		uint64(dialect),
	)
	if err != nil {
		return 0, fmt.Errorf("failed to call detect_sql_injection: %w", err)
	}
	if len(results) == 0 {
		return 0, fmt.Errorf("detect_sql_injection returned no results")
	}

	// Safely convert result to int32, checking for overflow
	result := results[0]
	if result > uint64(math.MaxInt32) {
		return 0, fmt.Errorf("detect_sql_injection returned value too large: %d", result)
	}
	return int32(result), nil
}

// allocateAndWriteString allocates memory for a string, writes it to WASM memory, and returns the pointer and length
// The caller is responsible for freeing the memory using the returned free function
func allocateAndWriteString(ctx context.Context, memory api.Memory, alloc, free api.Function, data []byte, name string) (uint32, uint64, func(), error) {
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

	// Create cleanup function
	cleanup := func() {
		if _, freeErr := free.Call(ctx, uint64(ptr), dataLen); freeErr != nil {
			// Log error but don't fail the main operation
			log.Error("Failed to free memory", slog.String("name", name), slog.Any("error", freeErr))
		}
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
