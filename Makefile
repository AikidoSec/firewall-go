.PHONY: test
test:
	@echo "Running tests"
	@go test ./...
	@echo "✅ Tests completed successfully"

.PHONY: lint
lint:
	@echo "Linting code"
	@gofmt -w .
