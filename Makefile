ZEN_INTERNALS_VERSION=v0.1.55
ORCHESTRION_VERSION=v1.6.1
GOLANGCI_LINT_VERSION=v2.8.0

TOOLS_BIN := $(shell pwd)/tools/bin

.PHONY: install-tools
install-tools:
	@echo "Installing gotestsum"
	@cd tools && GOBIN=$(TOOLS_BIN) go install gotest.tools/gotestsum
	@echo "✅ gotestsum installed successfully"
	@echo "Installing golangci-lint"
	@GOBIN=$(TOOLS_BIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	@echo "✅ golangci-lint installed successfully"
	@echo "Installing orchestrion"
	@GOBIN=$(TOOLS_BIN) go install github.com/DataDog/orchestrion
	@echo "✅ tools installed successfully"

.PHONY: clean-tools
clean-tools:
	@rm -rf $(TOOLS_BIN)
	@echo "✅ Cleaned tools/bin"

.PHONY: test
test: test-main test-zen-go
	@echo "✅ All tests completed successfully"

.PHONY: test-main
test-main:
	@echo "Running main module tests with gotestsum"
	@$(TOOLS_BIN)/gotestsum --format pkgname -- -race -coverprofile=coverage.out -covermode=atomic ./internal/... ./zen/...
	@echo "✅ Main module tests completed successfully"
	@echo "Coverage report saved to coverage.out"
	@go tool cover -func=coverage.out | grep total | awk '{print "Total coverage: " $$3}'

.PHONY: test-zen-go
test-zen-go:
	@echo "Running zen-go CLI tests with gotestsum"
	@cd cmd/zen-go && $(TOOLS_BIN)/gotestsum --format pkgname -- -race -coverprofile=coverage.out -covermode=atomic ./...
	@echo "✅ zen-go tests completed successfully"
	@cd cmd/zen-go && go tool cover -func=coverage.out | grep total | awk '{print "cmd/zen-go coverage: " $$3}'

.PHONY: test-db-start
test-db-start:
	@echo "Starting test database..."
	@cd instrumentation && docker compose -f docker-compose.test.yml up -d
	@echo "Waiting for database to be ready..."
	@timeout=30; \
	while ! docker exec instrumentation_test_postgres pg_isready -U testuser -d testdb >/dev/null 2>&1; do \
		timeout=$$((timeout - 1)); \
		if [ $$timeout -le 0 ]; then \
			echo "❌ Database failed to start within 30 seconds"; \
			exit 1; \
		fi; \
		sleep 1; \
	done
	@echo "✅ Test database is ready on port 5433"

.PHONY: test-db-stop
test-db-stop:
	@echo "Stopping test database..."
	@cd instrumentation && docker compose -f docker-compose.test.yml down
	@echo "✅ Test database stopped"

.PHONY: test-instrumentation-integration
test-instrumentation-integration: test-db-start
	@echo "Running instrumentation tests with orchestrion"
	@$(TOOLS_BIN)/gotestsum --format pkgname -- -race -coverprofile=coverage.out -covermode=atomic -toolexec="$(TOOLS_BIN)/orchestrion toolexec" -a -tags=integration ./instrumentation/sources/... ./instrumentation/sinks/... || \
		($(MAKE) test-db-stop && exit 1)
	@$(MAKE) test-db-stop
	@echo "✅ Instrumentation tests completed successfully"
	@echo "Coverage report saved to coverage.out"
	@go tool cover -func=coverage.out | grep total | awk '{print "Total coverage: " $$3}'

.PHONY: test-instrumentation-unit
test-instrumentation-unit:
	@echo "Running instrumentation unit tests"
	@rm -f coverage-*.out coverage.out
	@# Test subdirectories with go.mod
	@i=0; \
	for dir in instrumentation/; do \
		find $$dir -name go.mod -exec dirname {} \; | while read moddir; do \
			i=$$((i+1)); \
			echo "Testing module in $$moddir (unit tests)"; \
			cd $$moddir && $(TOOLS_BIN)/gotestsum --format pkgname -- -race -coverprofile=$(CURDIR)/coverage-$$i.out -covermode=atomic ./...; \
			cd $(CURDIR); \
		done; \
	done
	@# Test root module instrumentation packages (those without go.mod)
	@if go list ./instrumentation/... 2>/dev/null | grep -q .; then \
		echo "Testing root module instrumentation packages"; \
		$(TOOLS_BIN)/gotestsum --format pkgname -- -race -coverprofile=coverage-root-inst.out -covermode=atomic ./instrumentation/...; \
	fi
	@echo "Merging coverage reports..."
	@echo "mode: atomic" > coverage.out
	@find . -maxdepth 1 -name 'coverage-*.out' -exec tail -n +2 {} \; >> coverage.out
	@rm -f coverage-*.out
	@echo "✅ Instrumentation unit tests completed successfully"
	@echo "Coverage report saved to coverage.out"

.PHONY: test-coverage-html
test-coverage-html: test
	@echo "Generating HTML coverage report"
	@go tool cover -html=coverage.out -o coverage.html
	@echo "✅ Coverage report saved to coverage.html"

.PHONY: lint
lint:
	@echo "🔍 Linting all Go modules..."
	@echo "📦 Linting root module"
	@$(TOOLS_BIN)/golangci-lint run ./... $(FLAGS) || exit 1
	@for dir in $$(find . -name go.mod -not -path "./go.mod" -not -path "./tools/*" -exec dirname {} \;); do \
		echo "📦 Linting module in $$dir"; \
		(cd $$dir && $(TOOLS_BIN)/golangci-lint run $(FLAGS) ./...) || exit 1; \
	done
	@echo "✅ All modules linted successfully"

.PHONY: lint-integration
lint-integration:
	@echo "🔍 Linting modules in instrumentation/ with integration tag..."
	@for dir in $$(find ./instrumentation -name go.mod -exec dirname {} \; 2>/dev/null); do \
		echo "📦 Linting module in $$dir"; \
		(cd $$dir && $(TOOLS_BIN)/golangci-lint run --build-tags=integration $(FLAGS) ./...) || exit 1; \
	done
	@echo "✅ Integration linting completed successfully"

.PHONY: lint-fix
lint-fix:
	@$(MAKE) lint FLAGS=--fix
	@$(MAKE) lint-integration FLAGS=--fix

.PHONY: tidy
tidy:
	@echo "🧹 Running go mod tidy in all modules..."
	@echo "📦 Tidying root module"
	@go mod tidy
	@for dir in $$(find . -name go.mod -not -path "./go.mod" -exec dirname {} \;); do \
		echo "📦 Tidying module in $$dir"; \
		(cd $$dir && go mod tidy) || exit 1; \
	done
	@echo "✅ All modules tidied successfully"

BASE_URL = https://github.com/AikidoSec/zen-internals/releases/download/$(ZEN_INTERNALS_VERSION)
FILES = \
		libzen_internals.wasm \
		libzen_internals.wasm.sha256sum

.PHONY: binaries
binaries: clean-binaries download-binaries

clean-binaries:
	rm -f $(addprefix internal/vulnerabilities/zeninternals/, $(FILES))

download-binaries: $(addprefix internal/vulnerabilities/zeninternals/, $(FILES))

internal/vulnerabilities/zeninternals/%:
	@echo "Downloading $*..."
	curl -L -o $@ $(BASE_URL)/$*

.PHONY: check-orchestrion
check-orchestrion:
	@echo "Checking orchestrion versions across all modules..."
	@EXPECTED="$(ORCHESTRION_VERSION)"; \
	echo "Expected version: $$EXPECTED"; \
	echo ""; \
	FAILED=0; \
	check_module() { \
		local dir=$$1; \
		local label=$$2; \
		echo "$$label:"; \
		MOD_VERSION=$$(cd "$$dir" && go list -m -f '{{.Version}}' github.com/DataDog/orchestrion 2>/dev/null || echo "not found"); \
		if [ "$$MOD_VERSION" != "$$EXPECTED" ]; then \
			echo "  ❌ $$MOD_VERSION (expected $$EXPECTED)"; \
			return 1; \
		else \
			echo "  ✅ $$MOD_VERSION"; \
			return 0; \
		fi; \
	}; \
	check_module "." "Root module" || FAILED=1; \
	echo ""; \
	echo "Sample apps:"; \
	for dir in sample-apps/*/; do \
		if [ -f "$$dir/go.mod" ]; then \
			check_module "$$dir" "  $$dir" || FAILED=1; \
		fi \
	done; \
	if [ $$FAILED -eq 1 ]; then \
		echo ""; \
		echo "❌ Version mismatch detected. Run 'make sync-orchestrion' to fix."; \
		exit 1; \
	else \
		echo ""; \
		echo "✅ All modules use orchestrion $(ORCHESTRION_VERSION)"; \
	fi

.PHONY: sync-orchestrion
sync-orchestrion:
	@echo "Syncing orchestrion $(ORCHESTRION_VERSION) to all modules..."
	@go mod edit -require=github.com/DataDog/orchestrion@$(ORCHESTRION_VERSION)
	@go mod tidy
	@for dir in sample-apps/*/; do \
		if [ -f "$$dir/go.mod" ]; then \
			echo "  Updating $$dir"; \
			cd "$$dir" && \
				go mod edit -require=github.com/DataDog/orchestrion@$(ORCHESTRION_VERSION) && \
				go mod tidy && \
				cd ../..; \
		fi \
	done
	@echo "✅ All modules synced to orchestrion $(ORCHESTRION_VERSION)"
