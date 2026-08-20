#!/usr/bin/env bash
#
# Run golangci-lint for one or more Go modules in parallel.
# - Modules can be listed explicitly or discovered via --find
# - All modules are linted even if some fail
# - Output is prefixed per-module since jobs run concurrently
# - Exit code is non-zero if any module fails
#

set -uo pipefail

: "${TOOLS_BIN:?TOOLS_BIN must be set}"

modules=()
lint_args=()
max_jobs="${LINT_JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"

# --- argument parsing -------------------------------------------------

while [[ $# -gt 0 ]]; do
	case "$1" in
	--find)
		while IFS= read -r dir; do
			modules+=("$dir")
		done < <(find "$2" -name go.mod -exec dirname {} \;)
		shift 2
		;;
	--)
		shift
		lint_args=("$@")
		break
		;;
	*)
		modules+=("$1")
		shift
		;;
	esac
done

if [[ ${#modules[@]} -eq 0 ]]; then
	echo "No modules to lint"
	exit 0
fi

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# --- helpers ------------------------------------------------------------

lint_module() {
	local moddir=$1
	local statusfile=$2
	shift 2

	(
		cd "$moddir"
		"$TOOLS_BIN/golangci-lint" run --allow-parallel-runners "$@" ./...
	) 2>&1 | sed "s|^|[$moddir] |"

	echo "${PIPESTATUS[0]}" >"$statusfile"
}

# --- main ---------------------------------------------------------------

echo "🔍 Linting ${#modules[@]} module(s), up to $max_jobs in parallel..."

i=0
for moddir in "${modules[@]}"; do
	i=$((i + 1))
	echo "📦 Linting module in $moddir"

	lint_module "$moddir" "$tmpdir/status-$i" "${lint_args[@]}" &

	while (($(jobs -rp | wc -l) >= max_jobs)); do
		wait -n || true
	done
done

wait || true

failed=0
for statusfile in "$tmpdir"/status-*; do
	if [[ ! -s "$statusfile" || "$(<"$statusfile")" -ne 0 ]]; then
		failed=1
	fi
done

exit "$failed"
