#!/bin/bash
# scripts/run-all-suites.sh - Run all test suites sequentially
set -e

APP=$1
START_PORT=${2:-8080}

if [ -z "$APP" ]; then
	echo "Usage: $0 <app> [start-port]"
	echo "Example: $0 gin-postgres 8080"
	echo ""
	echo "This will run all test suites found in tests/"
	echo "Each suite gets its own port (incremented from start-port)"
	exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
END2END_DIR="$(dirname "$SCRIPT_DIR")"
TESTS_DIR="$END2END_DIR/tests"

# Find all test suite directories
SUITE_DIRS=$(find "$TESTS_DIR" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort)

if [ -z "$SUITE_DIRS" ]; then
	echo "❌ No test suites found in tests/"
	exit 1
fi

echo "Found test suites:"
echo "$SUITE_DIRS" | while read -r suite; do
	echo "  - $suite"
done
echo ""

# Run each suite
PORT=$START_PORT
FAILED_SUITES=()
PASSED_SUITES=()

for SUITE_NAME in $SUITE_DIRS; do
	echo ""
	echo "=========================================="
	echo "Suite $((PORT - START_PORT + 1)) of $(echo "$SUITE_DIRS" | wc -l | tr -d ' ')"
	echo "=========================================="
	
	if "$SCRIPT_DIR/run-suite.sh" "$SUITE_NAME" "$APP" "$PORT"; then
		PASSED_SUITES+=("$SUITE_NAME")
	else
		FAILED_SUITES+=("$SUITE_NAME")
		echo ""
		echo "⚠️  Suite '$SUITE_NAME' failed, but continuing with remaining suites..."
	fi
	
	PORT=$((PORT + 1))
	
	# Small delay between suites to ensure clean shutdown
	sleep 2
done

# Summary
echo ""
echo "=================================================="
echo "Test Suite Summary"
echo "=================================================="
echo ""
echo "Passed: ${#PASSED_SUITES[@]}"
for suite in "${PASSED_SUITES[@]}"; do
	echo "  ✓ $suite"
done

if [ ${#FAILED_SUITES[@]} -gt 0 ]; then
	echo ""
	echo "Failed: ${#FAILED_SUITES[@]}"
	for suite in "${FAILED_SUITES[@]}"; do
		echo "  ✗ $suite"
	done
	echo ""
	echo "❌ Some test suites failed"
	exit 1
fi

echo ""
echo "✓ All test suites passed!"
exit 0
