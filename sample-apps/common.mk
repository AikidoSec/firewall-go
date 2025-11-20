PORT ?= 8080
BINARY := bin/app

.PHONY: build run dev start-database stop-database clean

build:
	@mkdir -p bin
	@go build $(BUILD_FLAGS) -o $(BINARY) .

run: build
	@PORT=$(PORT) ./$(BINARY)

dev:
	@PORT=$(PORT) go run $(BUILD_FLAGS) .

start-database:
	@cd ../databases/ && docker compose up $(DB_SERVICE) -d

stop-database:
	@cd ../databases/ && docker compose down

clean:
	@rm -rf bin/

