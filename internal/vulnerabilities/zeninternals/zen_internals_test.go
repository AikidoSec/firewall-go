package zeninternals

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyWASMChecksum(t *testing.T) {
	parts := strings.Fields(checksumFile)
	require.Len(t, parts, 2, "invalid checksum file format")

	expectedHash := parts[0]

	hash := sha256.Sum256(wasmBin)
	actualHash := hex.EncodeToString(hash[:])

	require.Equal(t, expectedHash, actualHash, "checksums must match")
}

func TestNewWasmInstance(t *testing.T) {
	// Initialize the library first
	err := Init()
	if err != nil {
		t.Skipf("Skipping test due to initialization error: %v", err)
	}

	// Test that newWasmInstance returns the correct type
	instance := newWasmInstance()
	require.NotNil(t, instance, "newWasmInstance should not return nil")

	// Type assertion to verify it's a *wasmInstance
	_, ok := instance.(*wasmInstance)
	require.True(t, ok, "newWasmInstance should return *wasmInstance")
}

func TestDetectSQLInjection(t *testing.T) {
	require.NoError(t, Init())

	result := DetectSQLInjection("SELECT * FROM users", "user input", int(MySQL))
	require.Equal(t, 0, result)

	result = DetectSQLInjection("SELECT * FROM users WHERE id = '1' OR 1=1", "1' OR 1=1", int(MySQL))
	require.Equal(t, 1, result)
}

// mockMemoryWriter is a mock implementation of memoryWriter that can simulate write failures
type mockMemoryWriter struct {
	mu              sync.Mutex
	writeCallCount  int
	failOnWriteCall int // fail on the Nth write call (failOnWriteCall = N, -1 = never fail)
}

func newMockMemoryWriter() *mockMemoryWriter {
	return &mockMemoryWriter{
		failOnWriteCall: -1, // never fail by default
	}
}

func (m *mockMemoryWriter) Write(_ uint32, _ []byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeCallCount++

	// Fail on the specified write call
	return m.failOnWriteCall != m.writeCallCount
}

// mockFunctionCaller is a mock implementation of functionCaller
type mockFunctionCaller struct {
	mu          sync.Mutex
	callResults []uint64
	callCount   int
	callHandler func(ctx context.Context, params []uint64) ([]uint64, error)
}

func newMockFunctionCaller(results []uint64) *mockFunctionCaller {
	return &mockFunctionCaller{
		callResults: results,
	}
}

func (f *mockFunctionCaller) Call(ctx context.Context, params ...uint64) ([]uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callCount++
	if f.callHandler != nil {
		return f.callHandler(ctx, params)
	}
	return f.callResults, nil
}

// TestAllocateAndWriteStringHappyPath tests the happy path where allocation and write succeed.
func TestAllocateAndWriteStringHappyPath(t *testing.T) {
	ctx := context.Background()
	memory := newMockMemoryWriter()

	// Track free calls
	var freeCalled bool
	var freePtr uint64
	var freeSize uint64

	// Mock alloc function that returns a pointer
	mockAlloc := newMockFunctionCaller([]uint64{100})

	// Mock free function that tracks calls
	mockFree := &mockFunctionCaller{
		callHandler: func(ctx context.Context, params []uint64) ([]uint64, error) {
			freeCalled = true
			if len(params) >= 2 {
				freePtr = params[0]
				freeSize = params[1]
			}
			return []uint64{}, nil
		},
	}

	testData := []byte("test data")
	expectedPtr := uint32(100)
	expectedLen := uint64(len(testData))

	ptr, length, cleanup, err := allocateAndWriteString(ctx, memory, mockAlloc, mockFree, testData, "test")

	// Should succeed
	assert.NoError(t, err)
	assert.NotNil(t, cleanup, "cleanup function should be returned")
	assert.Equal(t, expectedPtr, ptr)
	assert.Equal(t, expectedLen, length)

	// Verify write was called (successfully, so writeCallCount should be 1)
	assert.Equal(t, 1, memory.writeCallCount)

	// Call cleanup should free the memory and return true
	assert.True(t, cleanup(), "cleanup should succeed")
	assert.True(t, freeCalled, "free should have been called")
	assert.Equal(t, uint64(ptr), freePtr, "free should be called with correct pointer")
	assert.Equal(t, expectedLen, freeSize, "free should be called with correct size")
}

// TestAllocateAndWriteStringMemoryWriteFailure tests that when memory write fails,
// the function properly handles the error and doesn't leak allocated memory.
func TestAllocateAndWriteStringMemoryWriteFailure(t *testing.T) {
	ctx := context.Background()
	memory := newMockMemoryWriter()

	// Mock alloc function that returns a pointer
	mockAlloc := newMockFunctionCaller([]uint64{100})
	mockFree := newMockFunctionCaller([]uint64{})

	testData := []byte("test data")

	// Test write failure
	memory.failOnWriteCall = 1 // fail on write

	ptr, length, cleanup, err := allocateAndWriteString(ctx, memory, mockAlloc, mockFree, testData, "test")

	// Should return error and nil cleanup
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write")
	assert.Equal(t, uint32(0), ptr)
	assert.Equal(t, uint64(0), length)
	assert.Nil(t, cleanup, "cleanup should be nil when allocation fails")
}

// TestCallDetectSQLSecondAllocationFailure tests the scenario where:
// 1. First allocation (query) succeeds
// 2. Second allocation (userInput) fails on memory write
// 3. First allocation is properly freed via defer
// 4. Function returns error and cleanupSucceeded=false
//
// Note: This test verifies cleanupSucceeded=false, which DetectSQLInjection uses to determine
// whether to return the instance to sync.Pool.
func TestCallDetectSQLSecondAllocationFailure(t *testing.T) {
	ctx := context.Background()
	memory := newMockMemoryWriter()

	// Track allocations and frees
	allocCalls := 0
	freeCalls := []struct {
		ptr  uint64
		size uint64
	}{}

	// Mock alloc function - returns pointer for each allocation
	mockAlloc := &mockFunctionCaller{
		callHandler: func(ctx context.Context, params []uint64) ([]uint64, error) {
			allocCalls++
			// Return different pointers for each allocation
			if allocCalls == 1 {
				return []uint64{100}, nil // first allocation at 100
			}
			return []uint64{200}, nil // second allocation at 200
		},
	}

	// Mock free function - tracks what gets freed
	mockFree := &mockFunctionCaller{
		callHandler: func(ctx context.Context, params []uint64) ([]uint64, error) {
			if len(params) >= 2 {
				freeCalls = append(freeCalls, struct {
					ptr  uint64
					size uint64
				}{ptr: params[0], size: params[1]})
			}
			return []uint64{}, nil
		},
	}

	mockDetectSQL := &mockFunctionCaller{
		callResults: []uint64{0}, // won't be called due to early return
	}

	// Make memory write fail on the second call (userInput write)
	memory.failOnWriteCall = 2

	result, cleanupSucceeded, err := callDetectSQL(
		ctx,
		memory,
		mockAlloc,
		mockFree,
		mockDetectSQL,
		"SELECT * FROM users", // query - should succeed
		"user input",          // userInput - should fail on write
		0,                     // dialect
	)

	// Verify error is returned
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write user input to memory")
	assert.Equal(t, int32(0), result)

	// Verify cleanupSucceeded is false (because we return early)
	assert.False(t, cleanupSucceeded, "cleanupSucceeded should be false when operation fails")

	// Verify first allocation was freed (defer should have executed)
	// The query allocation (ptr=100, size=len("SELECT * FROM users")) should be freed
	assert.Greater(t, len(freeCalls), 0, "at least one free should have been called")

	querySize := uint64(len("SELECT * FROM users"))
	foundQueryFree := false
	for _, freeCall := range freeCalls {
		if freeCall.ptr == 100 && freeCall.size == querySize {
			foundQueryFree = true
			break
		}
	}
	assert.True(t, foundQueryFree, "query allocation should have been freed via defer")

	// Verify detectSQL was never called
	assert.Equal(t, 0, mockDetectSQL.callCount, "detectSQL should not be called when allocation fails")
}

// TestCompilationAndPooling tests that:
// 1. Init() returns quickly (doesn't block on compilation)
// 2. Compilation happens in background and eventually completes
// 3. After compilation, new instances use the compiled module
func TestCompilationAndPooling(t *testing.T) {
	// Init should return quickly without blocking on compilation
	start := time.Now()
	require.NoError(t, Init())
	require.Less(t, time.Since(start), 100*time.Millisecond, "Init should not block on compilation")

	// Verify it works with interpreter mode
	result := DetectSQLInjection("SELECT * FROM users WHERE id = '1' OR 1=1", "1' OR 1=1", int(MySQL))
	require.Equal(t, 1, result)

	// Wait for compilation to complete
	require.Eventually(t, hasCompileFinished,
		10*time.Second, 100*time.Millisecond, "Compilation should complete")

	// After compilation, new instances should use compiled module
	inst := newWasmInstance()
	require.NotNil(t, inst)
	wasmInst, ok := inst.(*wasmInstance)
	require.True(t, ok)
	require.True(t, wasmInst.isCompiled, "Should use compiled module after compilation")

	// Verify it works
	result = DetectSQLInjection("SELECT * FROM users WHERE id = '1' OR 1=1", "1' OR 1=1", int(MySQL))
	require.Equal(t, 1, result)
}

// TestConcurrentAccess verifies thread safety with concurrent DetectSQLInjection calls
func TestConcurrentAccess(t *testing.T) {
	// Initialize if not already done
	if interpreterRuntime == nil {
		err := Init()
		require.NoError(t, err, "Init should succeed")
	}

	const numGoroutines = 10
	const callsPerGoroutine = 5

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < callsPerGoroutine; j++ {
				result := DetectSQLInjection(
					"SELECT * FROM users WHERE id = ?",
					"123",
					int(MySQL),
				)
				assert.Equal(t, 0, result, "Should not detect injection in safe query")
			}
		}()
	}

	wg.Wait()
}
