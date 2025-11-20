PORT ?= 8082

.PHONY: run build start-database

run:
	PORT=$(PORT) go run -toolexec="orchestrion toolexec" -v echo-postgres

build:
	go build -toolexec="orchestrion toolexec" -v echo-postgres

start-database:
	cd ../databases/ && docker compose up postgres_database -d
