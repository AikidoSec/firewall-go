#!/usr/bin/env bash
#
# Compare a package's benchmarks built vanilla vs. under zen-go toolexec.
# Samples are interleaved (alternating binaries) so machine drift affects both
# equally rather than biasing one run; results are compared with benchstat.
#
# Usage: scripts/bench-toolexec.sh <package> [count]
#   package   Go package to benchmark, e.g. ./benchmarks/sinks/os
#   count     benchstat samples per binary (default 10)
#
# Env:
#   TAGS       build tag for the benchmark file (e.g. sink_bench); omitted if empty
#   BENCH      -test.bench pattern (default '.')
#   BENCHTIME  -test.benchtime (default 1s)
#   VERIFY_RUN test run under toolexec to prove instrumentation is live
#              (default '^TestCompiledWithZenGo$'); set empty to skip
#   OUT_DIR    output dir (default: <repo>/bench-results/<derived-from-package>)
#

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PKG="${1:?usage: bench-toolexec.sh <package> [count]}"
COUNT="${2:-10}"
TAGS="${TAGS:-}"
BENCH="${BENCH:-.}"
BENCHTIME="${BENCHTIME:-1s}"
VERIFY_RUN="${VERIFY_RUN:-^TestCompiledWithZenGo$}"

label=$(echo "$PKG" | sed -e 's#^\./##' -e 's#[/.]#_#g')
OUT_DIR="${OUT_DIR:-$ROOT_DIR/bench-results/$label}"

# Assemble the optional -tags flag once.
tagflag=()
if [[ -n "$TAGS" ]]; then
	tagflag=(-tags="$TAGS")
fi

mkdir -p "$OUT_DIR"
rm -f "$OUT_DIR"/vanilla.* "$OUT_DIR"/zen.* "$OUT_DIR"/benchstat.txt

echo ">>> Building zen-go..."
make build-zen-go >/dev/null
ZEN_GO="$ROOT_DIR/tools/bin/zen-go"

if [[ -n "$VERIFY_RUN" ]]; then
	echo ">>> Verifying instrumentation is active under -toolexec ($VERIFY_RUN)..."
	go test "${tagflag[@]}" -run="$VERIFY_RUN" -count=1 -v \
		-toolexec="$ZEN_GO toolexec" "$PKG"
fi

VANILLA_BIN="$OUT_DIR/vanilla.test"
ZEN_BIN="$OUT_DIR/zen.test"

echo ">>> Building test binaries..."
go test "${tagflag[@]}" -c -o "$VANILLA_BIN" "$PKG"
go test "${tagflag[@]}" -c -o "$ZEN_BIN" -toolexec="$ZEN_GO toolexec" "$PKG"

run_sample() {
	local bin="$1" out="$2"
	"$bin" \
		-test.run='^$' \
		-test.bench="$BENCH" \
		-test.benchmem \
		-test.benchtime="$BENCHTIME" \
		-test.count=1 \
		>>"$out"
}

# benchstat reads the goos/goarch/pkg/cpu header to label results, so emit it
# once at the top of each file before the interleaved sample lines.
"$VANILLA_BIN" -test.run='^$' -test.bench='^$' >"$OUT_DIR/vanilla.txt"
"$ZEN_BIN" -test.run='^$' -test.bench='^$' >"$OUT_DIR/zen.txt"

echo ">>> Interleaving $COUNT samples per binary (benchtime=$BENCHTIME)..."
for ((i = 1; i <= COUNT; i++)); do
	printf '\r  sample %d/%d' "$i" "$COUNT"
	run_sample "$VANILLA_BIN" "$OUT_DIR/vanilla.txt"
	run_sample "$ZEN_BIN" "$OUT_DIR/zen.txt"
done
printf '\n'

echo ">>> Capturing profiles (single dedicated run each)..."
"$VANILLA_BIN" -test.run='^$' -test.bench="$BENCH" -test.benchtime="$BENCHTIME" \
	-test.cpuprofile="$OUT_DIR/vanilla.cpu.prof" \
	-test.memprofile="$OUT_DIR/vanilla.mem.prof" >/dev/null
"$ZEN_BIN" -test.run='^$' -test.bench="$BENCH" -test.benchtime="$BENCHTIME" \
	-test.cpuprofile="$OUT_DIR/zen.cpu.prof" \
	-test.memprofile="$OUT_DIR/zen.mem.prof" >/dev/null

echo
if command -v benchstat >/dev/null 2>&1; then
	benchstat "$OUT_DIR/vanilla.txt" "$OUT_DIR/zen.txt" | tee "$OUT_DIR/benchstat.txt"
else
	echo "benchstat not installed. To install:"
	echo "  go install golang.org/x/perf/cmd/benchstat@latest"
fi

cat <<EOF

Artefacts:    $OUT_DIR
CPU diff:     go tool pprof -diff_base $OUT_DIR/vanilla.cpu.prof $OUT_DIR/zen.cpu.prof
Mem diff:     go tool pprof -diff_base $OUT_DIR/vanilla.mem.prof $OUT_DIR/zen.mem.prof
Alloc diff:   go tool pprof -alloc_objects -diff_base $OUT_DIR/vanilla.mem.prof $OUT_DIR/zen.mem.prof
Zen CPU web:  go tool pprof -http=:8080 $OUT_DIR/zen.cpu.prof
Zen mem web:  go tool pprof -http=:8080 $OUT_DIR/zen.mem.prof

EOF
