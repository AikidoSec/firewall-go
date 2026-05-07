#!/usr/bin/env bash
#
# Run benchmarks for all Go modules that contain benchmark functions.
# Handles both root module packages and sub-modules with separate go.mod files.
# Exits non-zero if any benchmark run fails.
#

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

current_go_minor=$(go env GOVERSION | sed 's/^go1\.//' | cut -d. -f1)

# Directories containing at least one Benchmark function
bench_dirs=$(grep -rl "func Benchmark" --include="*_test.go" . \
    | xargs -n1 dirname \
    | sort -u \
    | sed 's|^\./||')

# Sub-module roots (has own go.mod, excludes repo root and tools/)
submods=$(find . -name go.mod \
    -not -path "./go.mod" \
    -not -path "./tools/*" \
    -exec dirname {} \; \
    | sed 's|^\./||')

failed=0
root_pkgs=()
declare -A sub_bench_mods

for d in $bench_dirs; do
    is_sub=0
    for m in $submods; do
        case "$d" in
            "$m"/*|"$m")
                is_sub=1
                sub_bench_mods["$m"]=1
                break
                ;;
        esac
    done
    if [[ $is_sub -eq 0 ]]; then
        root_pkgs+=("./$d")
    fi
done

if [[ ${#root_pkgs[@]} -gt 0 ]]; then
    echo "Running root module benchmarks: ${root_pkgs[*]}"
    go test -bench=. -benchmem -run='^$' "${root_pkgs[@]}" || failed=1
fi

for m in "${!sub_bench_mods[@]}"; do
    mod_minor=$(sed -n 's/^go 1\.//p' "$m/go.mod" | cut -d. -f1)
    if [[ -n "$mod_minor" ]] && ((mod_minor > current_go_minor)); then
        echo "Skipping $m benchmarks (requires go 1.$mod_minor, have go 1.$current_go_minor)"
        continue
    fi
    echo "Running benchmarks for sub-module: $m"
    (cd "$m" && go test -bench=. -benchmem -run='^$' ./...) || failed=1
done

exit "$failed"
