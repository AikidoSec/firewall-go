ZEN_INTERNALS_VERSION=v0.1.53

.PHONY: install-tools
install-tools:
	@echo "Installing gotestsum"
	@go install gotest.tools/gotestsum
	@echo "✅ gotestsum installed successfully"
	@echo "Installing golangci-lint"
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.62.2
	@echo "✅ golangci-lint installed successfully"
	@echo "Installing orchestrion"
	@go install github.com/DataDog/orchestrion
	@echo "✅ tools installed successfully"


.PHONY: test
test: test-main test-zen-go
	@echo "✅ All tests completed successfully"

.PHONY: test-main
test-main:
	@echo "Running main module tests with gotestsum"
	@gotestsum --format pkgname -- -race -coverprofile=coverage.out -covermode=atomic ./...
	@echo "✅ Main module tests completed successfully"
	@echo "Coverage report saved to coverage.out"
	@go tool cover -func=coverage.out | grep total | awk '{print "Total coverage: " $$3}'

.PHONY: test-zen-go
test-zen-go:
	@echo "Running zen-go CLI tests with gotestsum"
	@cd cmd/zen-go && gotestsum --format pkgname -- -race -coverprofile=coverage.out -covermode=atomic ./...
	@echo "✅ zen-go tests completed successfully"
	@cd cmd/zen-go && go tool cover -func=coverage.out | grep total | awk '{print "cmd/zen-go coverage: " $$3}'

.PHONY: test-instrumentation
test-instrumentation:
	@echo "Running instrumentation tests with orchestrion"
	@gotestsum --format pkgname -- -race -coverprofile=coverage.out -covermode=atomic -toolexec="orchestrion toolexec" -a -tags=integration ./instrumentation/sources/... ./instrumentation/sinks/...
	@echo "✅ Instrumentation tests completed successfully"
	@echo "Coverage report saved to coverage.out"
	@go tool cover -func=coverage.out | grep total | awk '{print "Total coverage: " $$3}'

.PHONY: test-coverage-html
test-coverage-html: test
	@echo "Generating HTML coverage report"
	@go tool cover -html=coverage.out -o coverage.html
	@echo "✅ Coverage report saved to coverage.html"

.PHONY: lint
lint:
	@echo "Linting code with golangci-lint"
	@golangci-lint run ./...
	@echo "✅ Linting completed successfully"

.PHONY: lint-fix
lint-fix:
	@echo "Linting and fixing code with golangci-lint"
	@golangci-lint run --fix ./...
	@echo "✅ Linting and fixing completed successfully"


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
