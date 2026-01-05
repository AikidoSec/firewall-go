MAKEFLAGS += --no-print-directory

.PHONY: run-suite test-all-suites list-suites test-interactive start-app stop-app

# Run a specific test suite
run-suite:
ifndef APP
	$(error APP is required. Usage: make run-suite SUITE=default APP=gin-postgres [PORT=8080])
endif
ifndef SUITE
	$(error SUITE is required. Usage: make run-suite SUITE=default APP=gin-postgres [PORT=8080])
endif
	@./scripts/run-suite.sh $(SUITE) $(APP) $(PORT)

# Run all test suites for an app
test-all-suites:
ifndef APP
	$(error APP is required. Usage: make test-all-suites APP=gin-postgres [PORT=8080])
endif
	@./scripts/run-all-suites.sh $(APP) $(PORT)

# List available test suites
list-suites:
	@echo "Available test suites:"
	@find tests -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort | sed 's/^/  - /'
	@echo ""
	@echo "Usage:"
	@echo "  Run one suite:  make run-suite SUITE=default APP=gin-postgres"
	@echo "  Run all suites: make test-all-suites APP=gin-postgres"

# Interactive testing with fzf
test-interactive:
	@if ! command -v fzf >/dev/null 2>&1; then \
		echo "❌ fzf is not installed. Install it with: brew install fzf"; \
		exit 1; \
	fi
	@APPS=$$(find ../sample-apps -mindepth 1 -maxdepth 1 -type d ! -name databases -exec basename {} \; | fzf --multi --prompt="Select apps to test (TAB to select multiple): " --height=40% --border); \
	if [ -z "$$APPS" ]; then \
		echo "No apps selected"; \
		exit 1; \
	fi; \
	for app in $$APPS; do \
		echo ""; \
		echo "=== Testing $$app ==="; \
		$(MAKE) test-all-suites APP=$$app || exit 1; \
	done; \
	echo ""; \
	echo "✓ All selected apps tested successfully"

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
