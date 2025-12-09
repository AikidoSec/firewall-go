PORT ?= 8080
BINARY := bin/app
ROOT_DIR := $(shell cd ../.. && pwd)
ORCHESTRION := $(ROOT_DIR)/tools/bin/orchestrion

export AIKIDO_BLOCK ?= true
export AIKIDO_DEBUG ?= true

.PHONY: build run dev start-database stop-database clean

build: check-orchestrion
	@mkdir -p bin
	@go build -toolexec="$(ORCHESTRION) toolexec" -o $(BINARY) .

run: build
	@PORT=$(PORT) ./$(BINARY)

dev: check-orchestrion
	@PORT=$(PORT) go run -toolexec="$(ORCHESTRION) toolexec" .

start-database:
	@cd ../databases/ && docker compose up $(DB_SERVICE) -d

stop-database:
	@cd ../databases/ && docker compose down

check-orchestrion:
	@test -f $(ORCHESTRION) || (echo "❌ orchestrion not found at $(ORCHESTRION). Run 'make install-tools' from project root" && exit 1)

clean:
	@rm -rf bin/
