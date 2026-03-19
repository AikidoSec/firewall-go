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

MOCK_PORT=$((PORT + 1000))
MOCK_PID_FILE="/tmp/mock-server-$MOCK_PORT.pid"
MOCK_LOG="/tmp/mock-server-$MOCK_PORT.log"
MOCK_BINARY="/tmp/end2end-mock-server"

stop_mock_server() {
	if [ -f "$MOCK_PID_FILE" ]; then
		MOCK_PID=$(cat "$MOCK_PID_FILE")
		kill "$MOCK_PID" 2>/dev/null || true
		rm -f "$MOCK_PID_FILE"
	fi
}

trap 'stop_mock_server; "$SCRIPT_DIR/stop-app.sh" "$APP" 2>/dev/null || true' EXIT

echo "=================================================="
echo "Running suite: $SUITE_NAME"
echo "App: $APP"
echo "Port: $PORT"
echo "Mock server port: $MOCK_PORT"
echo "Test directory: tests/$SUITE_NAME"

# Load environment variables from suite.env file if it exists
ENV_FILE="$TEST_DIR/suite.env"
if [ -f "$ENV_FILE" ]; then
	echo "Loading environment from: tests/$SUITE_NAME/suite.env"
	set -a # automatically export all variables
	source "$ENV_FILE"
	set +a

	# Show what was loaded
	echo "Environment variables:"
	while IFS= read -r line; do
		# Skip comments and empty lines
		[[ "$line" =~ ^#.*$ ]] && continue
		[[ -z "$line" ]] && continue
		echo "  - $line"
	done <"$ENV_FILE"
else
	echo "No suite.env file found (using defaults)"
fi

# Build mock server binary if needed
if [ ! -f "$MOCK_BINARY" ]; then
	echo "Building mock server..."
	(cd "$END2END_DIR/mock-server/" && go build -o "$MOCK_BINARY" .)
	echo "✓ Mock server built"
fi

# Start mock server
echo ""
echo "Starting mock server on port $MOCK_PORT..."
MOCK_SERVER_PORT=$MOCK_PORT "$MOCK_BINARY" >"$MOCK_LOG" 2>&1 &
echo $! >"$MOCK_PID_FILE"

# Wait for mock server to be ready
for i in {1..10}; do
	if curl -sf "http://localhost:$MOCK_PORT/mock/events" >/dev/null 2>&1; then
		echo "✓ Mock server ready on port $MOCK_PORT"
		break
	fi
	if [ "$i" -eq 10 ]; then
		echo "❌ Mock server failed to start. Logs:"
		cat "$MOCK_LOG"
		exit 1
	fi
	sleep 0.5
done

# Point the agent at the mock server
export AIKIDO_TOKEN=mock-token
export AIKIDO_ENDPOINT="http://localhost:$MOCK_PORT"
export AIKIDO_REALTIME_ENDPOINT="http://localhost:$MOCK_PORT"
export MOCK_SERVER_URL="http://localhost:$MOCK_PORT"

echo "=================================================="
echo ""

# Start the app with environment variables
echo "Starting app with configuration..."
"$SCRIPT_DIR/start-app.sh" "$APP" "$PORT"

# Read app config from apps.yml
APPS_CONFIG="$END2END_DIR/apps.yml"
APP_SQL_DIALECT=""
if [ -f "$APPS_CONFIG" ]; then
	APP_SQL_DIALECT=$(awk -v app="$APP" '
		/^[a-zA-Z]/ { current = substr($1, 1, length($1)-1) }
		current == app && /sql_dialect:/ { print $2; exit }
	' "$APPS_CONFIG")
fi

# Run the tests
echo ""
echo "Running tests..."
cd "$END2END_DIR"
PORT_VALUE=$(cat "/tmp/$APP.port")
APP_NAME=$APP APP_URL="http://localhost:$PORT_VALUE" APP_SQL_DIALECT=$APP_SQL_DIALECT go test -count=1 -v "./tests/$SUITE_NAME/..."
TEST_EXIT_CODE=$?

# Stop the app
echo ""
"$SCRIPT_DIR/stop-app.sh" "$APP"

# Stop mock server
stop_mock_server
trap - EXIT

if [ $TEST_EXIT_CODE -eq 0 ]; then
	echo "✓ Suite '$SUITE_NAME' passed"
else
	echo "❌ Suite '$SUITE_NAME' failed"
fi

exit $TEST_EXIT_CODE
