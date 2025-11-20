.PHONY: run
run:
	go run -toolexec="orchestrion toolexec" -v gin-postgres

build:
	go build -toolexec="orchestrion toolexec" -v gin-postgres

start-database:
	cd ../databases/ && docker compose up postgres_database -d
