#!/bin/bash
# scripts/run-suite.sh - Run a single test suite with its configuration
set -e

SUITE_NAME=$1
APP=$2
PORT=${3:-8080}

if [ -z "$SUITE_NAME" ] || [ -z "$APP" ]; then
	echo "Usage: $0 <suite-name> <app> [port]"
	echo "Example: $0 default gin-postgres 8080"
	exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
END2END_DIR="$(dirname "$SCRIPT_DIR")"
TEST_DIR="$END2END_DIR/tests/$SUITE_NAME"

if [ ! -d "$TEST_DIR" ]; then
	echo "❌ Suite directory not found: $TEST_DIR"
	exit 1
fi

echo "=================================================="
echo "Running suite: $SUITE_NAME"
echo "App: $APP"
echo "Port: $PORT"
echo "Test directory: tests/$SUITE_NAME"

# Load environment variables from suite.env file if it exists
ENV_FILE="$TEST_DIR/suite.env"
if [ -f "$ENV_FILE" ]; then
	echo "Loading environment from: tests/$SUITE_NAME/suite.env"
	set -a  # automatically export all variables
	source "$ENV_FILE"
	set +a
	
	# Show what was loaded
	echo "Environment variables:"
	while IFS= read -r line; do
		# Skip comments and empty lines
		[[ "$line" =~ ^#.*$ ]] && continue
		[[ -z "$line" ]] && continue
		echo "  - $line"
	done < "$ENV_FILE"
else
	echo "No suite.env file found (using defaults)"
fi

echo "=================================================="
echo ""

# Start the app with environment variables
echo "Starting app with configuration..."
"$SCRIPT_DIR/start-app.sh" "$APP" "$PORT"

# Run the tests
echo ""
echo "Running tests..."
cd "$END2END_DIR"
PORT_VALUE=$(cat "/tmp/$APP.port")
APP_NAME=$APP APP_URL="http://localhost:$PORT_VALUE" go test -count=1 -v "./tests/$SUITE_NAME/..."
TEST_EXIT_CODE=$?

# Stop the app
echo ""
"$SCRIPT_DIR/stop-app.sh" "$APP"

if [ $TEST_EXIT_CODE -eq 0 ]; then
	echo "✓ Suite '$SUITE_NAME' passed"
else
	echo "❌ Suite '$SUITE_NAME' failed"
fi

exit $TEST_EXIT_CODE
