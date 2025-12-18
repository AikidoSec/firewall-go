#!/bin/bash
# scripts/start-app.sh
set -e

APP=$1
PORT=${2:-8080}

if [ -z "$APP" ]; then
	echo "Usage: $0 <app> [port]"
	exit 1
fi

APP_DIR="../sample-apps/$APP"
LOG_FILE="/tmp/$APP.log"
PID_FILE="/tmp/$APP.pid"
PORT_FILE="/tmp/$APP.port"

# Check if already running
if [ -f "$PID_FILE" ]; then
	OLD_PID=$(cat "$PID_FILE")
	if ps -p $OLD_PID >/dev/null 2>&1; then
		echo "❌ $APP is already running with PID $OLD_PID"
		echo "   Stop it first with: make stop-app APP=$APP"
		exit 1
	else
		echo "⚠️  Cleaning up stale PID file"
		rm "$PID_FILE"
		rm -f "$PORT_FILE"
	fi
fi

# Check if port is already in use
if lsof -ti:$PORT -sTCP:LISTEN >/dev/null 2>&1; then
	EXISTING_PID=$(lsof -ti:$PORT -sTCP:LISTEN)
	echo "❌ Port $PORT is already in use by process $EXISTING_PID"
	# Check if it's one of our managed apps
	for existing_port_file in /tmp/*.port; do
		if [ -f "$existing_port_file" ] && [ "$(cat "$existing_port_file")" = "$PORT" ]; then
			EXISTING_APP=$(basename "$existing_port_file" .port)
			echo "   It appears to be managed by app: $EXISTING_APP"
			echo "   Stop it first with: make stop-app APP=$EXISTING_APP"
			break
		fi
	done
	exit 1
fi

echo "Starting $APP on port $PORT..."

# Start database
make -sC "$APP_DIR" start-database

# Start app in background
cd "$APP_DIR"
PORT=$PORT make run >"$LOG_FILE" 2>&1 &
APP_PID=$!
cd - >/dev/null

sleep 2

# Verify process is alive before writing PID file
if ! ps -p $APP_PID >/dev/null 2>&1; then
	echo "❌ App failed to start. Logs:"
	cat "$LOG_FILE"
	exit 1
fi

echo "✓ App process started with PID $APP_PID"
echo "Waiting for health check on port $PORT..."

# Wait for health check
for i in {1..180}; do
	if curl -sf "http://localhost:$PORT" >/dev/null 2>&1; then
		# Write both PID and PORT files after successful health check
		echo $APP_PID >"$PID_FILE"
		echo $PORT >"$PORT_FILE"
		echo "✓ $APP is ready on port $PORT!"
		echo "  Logs: $LOG_FILE"
		echo "  PID: $APP_PID"
		exit 0
	fi

	# Check if process died during startup
	if ! ps -p $APP_PID >/dev/null 2>&1; then
		echo ""
		echo "❌ App process died during startup. Logs:"
		cat "$LOG_FILE"
		exit 1
	fi

	printf "."
	sleep 1
done

# Timeout - kill the process since it never became healthy
echo ""
echo "❌ Timeout waiting for health check. Killing process $APP_PID..."
kill $APP_PID 2>/dev/null || true
sleep 1
ps -p $APP_PID >/dev/null 2>&1 && kill -9 $APP_PID 2>/dev/null || true

echo "Last 20 lines of logs:"
tail -20 "$LOG_FILE"
exit 1
