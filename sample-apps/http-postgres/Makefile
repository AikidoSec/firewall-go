PORT ?= 8084

.PHONY: run build start-database

run:
	PORT=$(PORT) go run -toolexec="orchestrion toolexec" -v http-postgres

build:
	go build -toolexec="orchestrion toolexec" -v http-postgres

start-database:
	cd ../databases/ && docker compose up postgres_database -d
