ZEN_INTERNALS_VERSION=v0.1.58
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

.PHONY: build-zen-go
build-zen-go:
	@cd cmd/zen-go && go build -o $(TOOLS_BIN)/zen-go .

.PHONY: clean-tools
clean-tools:
	@rm -rf $(TOOLS_BIN)
	@echo "✅ Cleaned tools/bin"

.PHONY: test
test: test-main test-zen-go
	@echo "✅ All tests completed successfully"

.PHONY: benchmark
benchmark:
	@echo "Running benchmarks..."
	@GIN_MODE=release go test -bench=. -benchmem -run=^$$ $$(grep -r "func Benchmark" --include="*_test.go" -l . | xargs -n1 dirname | sort -u)

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
	@echo "Running instrumentation tests with zen-go (coverage-enabled packages)"
	@$(TOOLS_BIN)/gotestsum --format pkgname -- \
		-race \
		-coverprofile=coverage.out \
		-covermode=atomic \
		-toolexec="$(TOOLS_BIN)/zen-go toolexec" \
		-tags=integration \
		./instrumentation/sources/net/http \
		./instrumentation/sinks/net/http \
		./instrumentation/sinks/os \
		./instrumentation/sinks/os/exec \
		./instrumentation/sinks/path \
		./instrumentation/sinks/path/filepath

	@echo "Running instrumentation tests without coverage (root module)"
	@$(TOOLS_BIN)/gotestsum --format pkgname -- \
		-race \
		-toolexec="$(TOOLS_BIN)/zen-go toolexec" \
		-tags=integration \
		./instrumentation/sinks/database/sql

	@echo "Running instrumentation tests without coverage (separate modules)"
	@TOOLS_BIN=$(TOOLS_BIN) ./scripts/test-modules.sh \
		instrumentation/sources/gin-gonic/gin \
		instrumentation/sources/go-chi/chi.v5 \
		instrumentation/sources/labstack/echo.v4 \
		instrumentation/sinks/jackc/pgx.v5 \
		-- -race -toolexec="$(TOOLS_BIN)/zen-go toolexec" -tags=integration

	@$(MAKE) test-db-stop
	@echo "✅ Instrumentation tests completed successfully"
	@echo "Coverage report saved to coverage.out"
	@go tool cover -func=coverage.out | grep total | awk '{print "Total coverage: " $$3}'

.PHONY: test-instrumentation-unit
test-instrumentation-unit:
	@echo "Running instrumentation unit tests"
	@rm -f coverage-*.out coverage.out
	@# Test subdirectories with go.mod
	@TOOLS_BIN=$(TOOLS_BIN) ./scripts/test-modules.sh \
		--find instrumentation/ \
		--coverage-dir $(CURDIR) \
		-- -race
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

INSTRUMENTATION_MODULES := $(shell find instrumentation -name go.mod -exec dirname {} \;)

.PHONY: update-instrumentation
update-instrumentation:
	@for dir in $(INSTRUMENTATION_MODULES); do \
		echo "📦 Updating $$dir"; \
		cd $$dir && \
		go get github.com/AikidoSec/firewall-go@latest && \
		go mod tidy && \
		cd $(CURDIR); \
	done
	@echo "✅ All instrumentation modules updated"

.PHONY: tag-instrumentation
tag-instrumentation:
ifndef VERSION
	$(error VERSION is required. Usage: make tag-instrumentation VERSION=0.1.0)
endif
	@for dir in $(INSTRUMENTATION_MODULES); do \
		echo "🏷️ Tagging $$dir/v$(VERSION)"; \
		git tag "$$dir/v$(VERSION)"; \
	done
	@echo "✅ All instrumentation modules tagged with v$(VERSION)"

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

