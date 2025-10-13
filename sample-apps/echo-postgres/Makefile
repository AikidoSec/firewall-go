.PHONY: run
run:
	go clean -a
	go clean -cache
	go run -toolexec="orchestrion toolexec" -v echo-postgres

build:
	go build -toolexec="orchestrion toolexec" -v echo-postgres
