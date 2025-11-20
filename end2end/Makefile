MAKEFLAGS += --no-print-directory

.PHONY: start-app stop-app run-tests test-app

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

run-tests:
ifndef APP
	$(error APP is required. Usage: make run-tests APP=gin-postgres)
endif
	@if [ ! -f /tmp/$(APP).port ]; then \
		echo "❌ $(APP) is not running. Start it first with: make start-app APP=$(APP)"; \
		exit 1; \
	fi
	@PORT=$$(cat /tmp/$(APP).port); \
	echo "Running tests against $(APP) on port $$PORT..."; \
	APP_NAME=$(APP) APP_URL=http://localhost:$$PORT go test -v ./tests/...

# Start app, run tests, then stop app
test-app:
ifndef APP
	$(error APP is required. Usage: make test-app APP=gin-postgres [PORT=8080])
endif
	@$(MAKE) start-app APP=$(APP) $(if $(PORT),PORT=$(PORT),) || exit 1
	@$(MAKE) run-tests APP=$(APP) || ($(MAKE) stop-app APP=$(APP); exit 1)
	@$(MAKE) stop-app APP=$(APP)
	@echo "✓ All tests completed successfully"
