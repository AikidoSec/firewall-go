#!/bin/bash
# scripts/stop-app.sh
set -e

APP=$1

if [ -z "$APP" ]; then
	echo "Usage: $0 <app>"
	exit 1
fi

PID_FILE="/tmp/$APP.pid"
APP_DIR="../sample-apps/$APP"

if [ -f "$PID_FILE" ]; then
	PID=$(cat "$PID_FILE")
	echo "Stopping $APP (PID: $PID)..."

	if ps -p $PID >/dev/null 2>&1; then
		# Try graceful shutdown first
		kill $PID 2>/dev/null || true

		# Wait up to 5 seconds for graceful shutdown
		for i in {1..5}; do
			if ! ps -p $PID >/dev/null 2>&1; then
				echo "✓ Stopped $APP gracefully"
				break
			fi
			sleep 1
		done

		# Force kill if still running
		if ps -p $PID >/dev/null 2>&1; then
			echo "⚠️  Process didn't stop gracefully, force killing..."
			kill -9 $PID 2>/dev/null || true
			sleep 1

			if ps -p $PID >/dev/null 2>&1; then
				echo "❌ Failed to kill process $PID"
				exit 1
			fi
			echo "✓ Force killed $APP"
		fi
	else
		echo "⚠️  Process $PID not running"
	fi

	rm "$PID_FILE"
else
	echo "⚠️  No PID file found for $APP"

	# Try to find and kill any running instances by name
	echo "Searching for running $APP processes..."
	PIDS=$(pgrep -f "sample-apps/$APP/bin/app" || true)
	if [ -n "$PIDS" ]; then
		echo "Found processes: $PIDS"
		echo "$PIDS" | xargs kill 2>/dev/null || true
		sleep 1
		echo "$PIDS" | xargs kill -9 2>/dev/null || true
	fi
fi

# Stop database
echo "Stopping database..."
make -sC "$APP_DIR" stop-database 2>/dev/null || true

echo "✓ Cleanup complete"
