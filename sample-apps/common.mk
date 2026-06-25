PORT ?= 8080
BINARY := bin/app
ROOT_DIR := $(shell cd ../.. && pwd)

export AIKIDO_BLOCK ?= true
export AIKIDO_DEBUG ?= true

.PHONY: build run dev start-database stop-database clean

build:
	@mkdir -p bin
	@go tool zen-go go build -o $(BINARY) .

run: build
	@PORT=$(PORT) ./$(BINARY)

dev:
	@PORT=$(PORT) go tool zen-go go run .

start-database:
	@cd ../databases/ && docker compose up $(DB_SERVICE) -d --wait

stop-database:
	@cd ../databases/ && docker compose down

clean:
	@rm -rf bin/
