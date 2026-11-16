package zeninternals

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

func (m *mockMemoryWriter) WriteString(_ uint32, _ string) bool {
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

func (f *mockFunctionCaller) CallWithStack(ctx context.Context, stack []uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callCount++
	results := f.callResults
	if f.callHandler != nil {
		var err error
		results, err = f.callHandler(ctx, stack)
		if err != nil {
			return err
		}
	}
	copy(stack, results)
	return nil
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

	testData := "test data"
	expectedPtr := uint32(100)
	expectedLen := uint64(len(testData))

	var stack [5]uint64
	ptr, length, cleanup, err := allocateAndWriteString(ctx, memory, mockAlloc, mockFree, stack[:], testData, "test")

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

	testData := "test data"

	// Test write failure
	memory.failOnWriteCall = 1 // fail on write

	var stack [5]uint64
	ptr, length, cleanup, err := allocateAndWriteString(ctx, memory, mockAlloc, mockFree, stack[:], testData, "test")

	// Should return error and nil cleanup
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write")
	assert.Equal(t, uint32(0), ptr)
	assert.Equal(t, uint64(0), length)
	assert.Nil(t, cleanup, "cleanup should be nil when allocation fails")
}

// TestCallDetectSQLCleanup tests the scenarios where:
// 1. Both deferred cleanup calls succeed
// 2. The user input cleanup fails
// 3. The query cleanup fails
// 4. Both cleanup calls are attempted even if one fails
//
// Note: The function reaches its normal return before deferred cleanup runs,
// this test verifies cleanup failures are properly returned to the caller.
func TestCallDetectSQLCleanup(t *testing.T) {
	// Test each possible individual cleanup failure and the successful case
	for _, tt := range []struct {
		name           string
		failOnFreeCall int
	}{
		{name: "both frees succeed", failOnFreeCall: -1},
		{name: "user input free fails", failOnFreeCall: 1},
		{name: "query free fails", failOnFreeCall: 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Mock free function that fails on the configured call
			freeCalls := 0
			free := &mockFunctionCaller{
				callHandler: func(_ context.Context, _ []uint64) ([]uint64, error) {
					freeCalls++
					if freeCalls == tt.failOnFreeCall {
						return nil, errors.New("free failed")
					}
					return nil, nil
				},
			}

			// Call detection with successful allocation and detection mocks
			var stack [5]uint64
			result, cleanupSucceeded, err := callDetectSQL(
				context.Background(), newMockMemoryWriter(), newMockFunctionCaller([]uint64{100}), free,
				newMockFunctionCaller([]uint64{1}), stack[:], "SELECT * FROM users", "user input", int(MySQL),
			)

			// Verify the detection succeeds and cleanup status reaches the caller
			require.NoError(t, err)
			assert.Equal(t, int32(1), result, "cleanup failures should preserve the detection result")
			assert.Equal(t, tt.failOnFreeCall == -1, cleanupSucceeded)

			// Verify both deferred cleanups run even if one fails
			assert.Equal(t, 2, freeCalls, "both cleanups should run even if one fails")
		})
	}
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

	var stack [5]uint64
	result, cleanupSucceeded, err := callDetectSQL(
		ctx,
		memory,
		mockAlloc,
		mockFree,
		mockDetectSQL,
		stack[:],
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

// WASM functions write results into the same buffer used for their arguments.
// Verify each call replaces old values and cleanup uses the original pointers.
func TestCallDetectSQLStackReuse(t *testing.T) {
	ctx := context.Background()
	stack := [5]uint64{99, 99, 99, 99, 99}
	for _, tc := range []struct {
		query, input string
		dialect      DatabaseType
		want         uint64
	}{
		{"SELECT * FROM users", "alice", PostgreSQL, 1},
		{"SELECT 1", "bob-smith", SQLite, 0},
	} {
		allocations := 0
		alloc := &mockFunctionCaller{callHandler: func(_ context.Context, params []uint64) ([]uint64, error) {
			allocations++
			if allocations == 1 {
				require.Equal(t, []uint64{uint64(len(tc.query))}, params)
				return []uint64{100}, nil
			}
			require.Equal(t, []uint64{uint64(len(tc.input))}, params)
			return []uint64{200}, nil
		}}
		detect := &mockFunctionCaller{callHandler: func(_ context.Context, params []uint64) ([]uint64, error) {
			require.Equal(t, []uint64{100, uint64(len(tc.query)), 200, uint64(len(tc.input)), uint64(tc.dialect)}, params)
			return []uint64{tc.want, 88, 88, 88, 88}, nil
		}}
		frees := 0
		free := &mockFunctionCaller{callHandler: func(_ context.Context, params []uint64) ([]uint64, error) {
			frees++
			if frees == 1 {
				require.Equal(t, []uint64{200, uint64(len(tc.input))}, params)
			} else {
				require.Equal(t, []uint64{100, uint64(len(tc.query))}, params)
			}
			return []uint64{77, 77}, nil
		}}
		result, cleaned, err := callDetectSQL(ctx, newMockMemoryWriter(), alloc, free, detect, stack[:], tc.query, tc.input, int(tc.dialect))
		require.NoError(t, err)
		require.True(t, cleaned)
		require.Equal(t, int32(tc.want), result)
		require.Equal(t, 2, frees)
	}
}

func TestCallDetectSQLStackErrors(t *testing.T) {
	for _, tc := range []struct {
		name, wantError string
		failAllocCall   int
		detectError     bool
		allocResult     uint64
		detectResult    uint64
		wantFrees       int
	}{
		{"allocation error", "failed to allocate memory for query", 1, false, 100, 1, 0},
		{"second allocation error", "failed to allocate memory for user input", 2, false, 100, 1, 1},
		{"pointer overflow", "pointer too large", 0, false, 1 << 32, 1, 0},
		{"detection error", "failed to call detect_sql_injection", 0, true, 100, 1, 2},
		{"result overflow", "returned value too large", 0, false, 100, 1 << 31, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stack := [5]uint64{1, 1, 1, 1, 1}
			memory := newMockMemoryWriter()
			callErr := errors.New("WASM function failed after writing to the argument/result buffer")
			allocCalls := 0
			alloc := &mockFunctionCaller{callHandler: func(_ context.Context, params []uint64) ([]uint64, error) {
				allocCalls++
				params[0] = tc.allocResult
				if allocCalls == tc.failAllocCall {
					return nil, callErr
				}
				return nil, nil
			}}
			detect := &mockFunctionCaller{callHandler: func(_ context.Context, params []uint64) ([]uint64, error) {
				params[0] = tc.detectResult
				if tc.detectError {
					return nil, callErr
				}
				return nil, nil
			}}
			free := &mockFunctionCaller{callHandler: func(_ context.Context, params []uint64) ([]uint64, error) {
				if tc.failAllocCall == 2 {
					require.Equal(t, []uint64{100, uint64(len("SELECT 1"))}, params)
				}
				return nil, nil
			}}
			result, cleaned, err := callDetectSQL(context.Background(), memory, alloc, free, detect, stack[:], "SELECT 1", "input", int(PostgreSQL))
			require.ErrorContains(t, err, tc.wantError)
			require.Zero(t, result)
			require.False(t, cleaned)
			require.Equal(t, tc.wantFrees, free.callCount)
			if tc.failAllocCall != 0 {
				require.ErrorIs(t, err, callErr)
				require.Equal(t, tc.failAllocCall, allocCalls)
				require.Equal(t, tc.failAllocCall-1, memory.writeCallCount)
				require.Zero(t, detect.callCount)
			}
		})
	}
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
	require.True(t, inst.isCompiled, "Should use compiled module after compilation")

	// Verify it works
	result = DetectSQLInjection("SELECT * FROM users WHERE id = '1' OR 1=1", "1' OR 1=1", int(MySQL))
	require.Equal(t, 1, result)
}

// Mixed results and input lengths help detect buffers shared between requests.
func TestConcurrentAccess(t *testing.T) {
	require.NoError(t, Init())
	cases := []struct {
		query, input string
		want         int
	}{
		{"SELECT * FROM users WHERE id = ?", "123", 0},
		{"SELECT * FROM users WHERE name = 'alice-smith'", "alice-smith", 0},
		{"SELECT * FROM users WHERE id = '1' OR 1=1", "1' OR 1=1", 1},
	}

	const numGoroutines = 10
	const callsPerGoroutine = 20

	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	start := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < callsPerGoroutine; j++ {
				tc := cases[(i+j)%len(cases)]
				result := DetectSQLInjection(tc.query, tc.input, int(MySQL))
				assert.Equal(t, tc.want, result, "query=%q input=%q", tc.query, tc.input)
			}
		}()
	}

	close(start)
	wg.Wait()
}

// TestDetectSQLInjection_ErrorPath tests that errors are handled without panicking
// and the system continues to work after errors
func TestDetectSQLInjection_ErrorPath(t *testing.T) {
	require.NoError(t, Init())

	// Normal operation
	result := DetectSQLInjection("SELECT * FROM users WHERE id = ?", "123", int(MySQL))
	assert.Equal(t, 0, result, "Should not detect injection in safe query")

	// Invalid dialect causes error
	result = DetectSQLInjection("SELECT * FROM users", "input", 999)
	assert.Equal(t, 0, result, "Should return 0 on error")

	// Normal operation after error should still work
	result = DetectSQLInjection("SELECT * FROM users WHERE id = ?", "123", int(MySQL))
	assert.Equal(t, 0, result, "Should work normally after error")

	// Multiple errors
	for range 10 {
		result = DetectSQLInjection("SELECT * FROM users", "input", 999)
		assert.Equal(t, 0, result, "Should return 0 on error")
	}

	// System should still work
	result = DetectSQLInjection("SELECT * FROM users WHERE id = '1' OR 1=1", "1' OR 1=1", int(MySQL))
	assert.Equal(t, 1, result, "Should still detect SQL injection after errors")
}
