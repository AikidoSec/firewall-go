.PHONY: start-app stop-app test-app

start-app:
ifndef APP
	$(error APP is required. Usage: make start-app APP=gin-postgres [PORT=8080])
endif
	@./scripts/start-app.sh $(APP) $(PORT)

stop-app:
ifndef APP
	$(error APP is required. Usage: make stop-app APP=gin-postgres)
endif
	@./scripts/stop-app.sh $(APP)

test-app:
ifndef APP
	$(error APP is required. Usage: make test APP=gin-postgres)
endif
	@if [ ! -f /tmp/$(APP).port ]; then \
		echo "❌ $(APP) is not running. Start it first with: make start-app APP=$(APP)"; \
		exit 1; \
	fi
	@PORT=$$(cat /tmp/$(APP).port); \
	echo "Running tests against $(APP) on port $$PORT..."; \
	APP_NAME=$(APP) APP_URL=http://localhost:$$PORT go test -v ./tests/...
