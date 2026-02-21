#!/usr/bin/env bash
#
# Run gotestsum for one or more Go modules.
# - Modules can be listed explicitly or discovered via --find
# - All modules are tested even if some fail
# - Exit code is non-zero if any module fails
#

set -euo pipefail

: "${TOOLS_BIN:?TOOLS_BIN must be set}"

coverage_dir=""
modules=()
test_args=()

current_go_minor=$(go env GOVERSION | sed 's/^go1\.//' | cut -d. -f1)

# --- argument parsing -------------------------------------------------

while [[ $# -gt 0 ]]; do
	case "$1" in
	--find)
		while IFS= read -r dir; do
			modules+=("$dir")
		done < <(find "$2" -name go.mod -exec dirname {} \;)
		shift 2
		;;
	--coverage-dir)
		coverage_dir="$2"
		shift 2
		;;
	--)
		shift
		test_args=("$@")
		break
		;;
	*)
		modules+=("$1")
		shift
		;;
	esac
done

# --- helpers ----------------------------------------------------------

run_tests() {
	local moddir=$1
	shift

	(
		cd "$moddir"
		"$TOOLS_BIN/gotestsum" --format pkgname -- "$@" ./...
	)
}

# --- main -------------------------------------------------------------

if [[ ${#modules[@]} -eq 0 ]]; then
	echo "No modules to test"
	exit 0
fi

failed=0
i=0

for moddir in "${modules[@]}"; do
	i=$((i + 1))

	mod_minor=$(sed -n 's/^go 1\.//p' "$moddir/go.mod" | cut -d. -f1)
	if [[ -n "$mod_minor" ]] && ((mod_minor > current_go_minor)); then
		echo "Skipping $moddir (requires go 1.$mod_minor, have go 1.$current_go_minor)"
		continue
	fi

	echo "Running tests for $moddir"

	cov_args=()
	if [[ -n "$coverage_dir" ]]; then
		cov_args=(
			-coverprofile="$coverage_dir/coverage-$i.out"
			-covermode=atomic
		)
	fi

	if ! run_tests "$moddir" "${test_args[@]}" "${cov_args[@]}"; then
		failed=1
	fi
done

exit "$failed"
