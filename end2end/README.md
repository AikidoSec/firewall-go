# End-2-End Tests

Tests are organized into suites. Each suite can have different environment variables set at app startup.

## Quick Start

```bash
# List available test suites
make list-suites

# Run all test suites
make test-all-suites APP=gin-postgres

# Run a specific suite
make run-suite SUITE=default APP=gin-postgres

# Choose which apps to run for tests
make test-interactive
```

## How It Works

Tests are organized by directory under `tests/`. Each directory is a test suite.

If a suite needs custom environment variables, create a `suite.env` file in that directory:

```bash
tests/
  default/
    suite.env               # Optional: env vars for this suite
    sql_injection_test.go
  blocking-enabled/
    suite.env               # AIKIDO_BLOCKING=true
    blocking_test.go
```

When you run a suite, the script:
1. Loads env vars from the suite's `suite.env` file (if it exists)
2. Starts the app with those env vars
3. Runs the tests
4. Stops the app

When running all suites, each gets a different port to avoid conflicts.

## Adding a New Suite

1. Create the directory:
```bash
mkdir -p tests/my-suite
```

2. Add a `suite.env` file if you need custom env vars:
```bash
# tests/my-suite/suite.env
MY_VAR=value
ANOTHER_VAR=another-value
```

3. Write tests in that directory. They'll read `APP_URL` from the environment.

4. Run it:
```bash
make run-suite SUITE=my-suite APP=gin-postgres
```

## Manual Control

For debugging, you can manually start/stop an app:

```bash
make start-app APP=gin-postgres PORT=8080
# ... manually test, debug, etc ...
make stop-app APP=gin-postgres
```
