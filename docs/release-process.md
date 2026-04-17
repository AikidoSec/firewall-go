# firewall-go Release Process

## 1. Bump the version

Update the version constant in `internal/agent/config/globals.go`:

```go
Version = "1.2.1"
```

## 2. Create a beta release

In the GitHub UI, create a pre-release tag (e.g. `v1.2.1-beta.1`) on the bump commit.

## 3. Tag instrumentation packages for beta

On the same commit, create beta tags for all instrumentation packages:

```bash
make tag-instrumentation VERSION=1.2.1-beta.1
git push --tags
```

## 4. Test against zen-demo-go

Update zen-demo-go to the beta version and test:

```bash
go get -u github.com/AikidoSec/firewall-go/...@v1.2.1-beta.1
```

Run through test scenarios.

## 5. Create the final release

Once happy with beta testing, create the final release tag (e.g. `v1.2.1`) in the GitHub UI.

## 6. Update instrumentation packages to the final version

Create a PR that updates all instrumentation packages to the new release:

```bash
make update-instrumentation
make tidy
```

Commit, push, and open a PR. The `update-instrumentation` target updates each instrumentation module to use the latest firewall-go, and `tidy` keeps sample app dependencies in sync.

## 7. Tag instrumentation packages for the final release

After the PR is merged, create tags locally:

```bash
make tag-instrumentation VERSION=1.2.1
git push --tags
```

## 8. Update zen-demo-go to the final version

```bash
go get -u github.com/AikidoSec/firewall-go/...@v1.2.1
```

Test again to confirm the release is stable.
