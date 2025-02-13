.PHONY: env
env:
	export PATH="$PATH:/var/home/primary/go/bin"
.PHONY: run
run:
	go clean -a
	go clean -cache
	go run -toolexec="orchestrion toolexec" -v gin-postgres
