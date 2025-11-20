.PHONY: start-app stop-app test

start-app:
ifndef APP
	$(error APP is required. Usage: make start-app APP=gin-postgres [PORT=8080])
endif
	@./scripts/start-app.sh $(APP) $(PORT)

stop-app:
ifndef APP
	$(error APP is required. Usage: make stop-app APP=gin-postgres)
endif
	@./scripts/stop-app.sh $(APP)

test:
ifndef APP
	$(error APP is required. Usage: make test APP=gin-postgres PORT=8080)
endif
ifndef PORT
	$(error PORT is required. Usage: make test APP=gin-postgres PORT=8080)
endif
	@echo "Running tests against $(APP) on port $(PORT)..."
	@APP_NAME=$(APP) APP_URL=http://localhost:$(PORT) go test -v ./tests/...

