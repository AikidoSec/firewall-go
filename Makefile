.PHONY: prepare
prepare: check_binaries
	mkdir -p /opt/aikido/lib
	cp .cache/binaries/* /opt/aikido/lib/

.PHONY: install-tools
install-tools:
	@echo "Installing gotestsum"
	@go install gotest.tools/gotestsum
	@echo "✅ gotestsum installed successfully"


.PHONY: test
test: prepare
	@echo "Running tests with gotestsum"
	@gotestsum --format pkgname -- -coverprofile=coverage.out -covermode=atomic ./...
	@echo "✅ Tests completed successfully"
	@echo "Coverage report saved to coverage.out"
	@go tool cover -func=coverage.out | grep total | awk '{print "Total coverage: " $$3}'

.PHONY: test-coverage-html
test-coverage-html: test
	@echo "Generating HTML coverage report"
	@go tool cover -html=coverage.out -o coverage.html
	@echo "✅ Coverage report saved to coverage.html"

.PHONY: lint
lint:
	@echo "Linting code"
	@gofmt -w .


BASE_URL = https://github.com/AikidoSec/zen-internals/releases/download/v0.1.37
FILES = \
    libzen_internals_aarch64-apple-darwin.dylib \
    libzen_internals_aarch64-apple-darwin.dylib.sha256sum \
    libzen_internals_aarch64-unknown-linux-gnu.so \
    libzen_internals_aarch64-unknown-linux-gnu.so.sha256sum \
    libzen_internals_x86_64-apple-darwin.dylib \
    libzen_internals_x86_64-apple-darwin.dylib.sha256sum \
    libzen_internals_x86_64-pc-windows-gnu.dll \
    libzen_internals_x86_64-pc-windows-gnu.dll.sha256sum \
    libzen_internals_x86_64-unknown-linux-gnu.so \
    libzen_internals_x86_64-unknown-linux-gnu.so.sha256sum

binaries: binaries_make_dir $(addprefix .cache/binaries/, $(FILES))
binaries_make_dir:
	rm -rf .cache/binaries
	mkdir -p .cache/binaries/
.cache/binaries/%:
	@echo "Downloading $*..."
	curl -L -o $@ $(BASE_URL)/$*

.PHONY: check_binaries
check_binaries:
	@if [ -d ".cache/binaries" ]; then \
			echo "Cache directory exists."; \
	else \
			echo "Cache directory is empty. Running 'make binaries'..."; \
			$(MAKE) binaries; \
	fi
