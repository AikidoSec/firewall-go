PORT ?= 8080
BINARY := bin/app
ROOT_DIR := $(shell cd ../.. && pwd)
ZENGO := $(ROOT_DIR)/tools/bin/zen-go

export AIKIDO_BLOCK ?= true
export AIKIDO_DEBUG ?= true

.PHONY: build run dev start-database stop-database clean

build: check-zen-go
	@mkdir -p bin
	@$(ZENGO) go build -o $(BINARY) .

run: build
	@PORT=$(PORT) ./$(BINARY)

dev: check-zen-go
	@PORT=$(PORT) $(ZENGO) go run .

start-database:
	@cd ../databases/ && docker compose up $(DB_SERVICE) -d --wait

stop-database:
	@cd ../databases/ && docker compose down

check-zen-go:
	@test -f $(ZENGO) || (echo "❌ zen-go not found at $(ZENGO). Run 'make build-zen-go' from project root" && exit 1)

clean:
	@rm -rf bin/
