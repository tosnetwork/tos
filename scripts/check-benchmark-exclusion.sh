#!/usr/bin/env bash
set -euo pipefail

repo=${1:-$(cd "$(dirname "$0")/.." && pwd)}

for tool in grep git; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "BENCHMARK_EXCLUSION_SOURCE_FAILURE: required tool '$tool' is unavailable" >&2
    exit 1
  fi
done

require_exact() {
  local file=$1
  local marker=$2
  local count
  if [[ ! -f "$repo/$file" ]]; then
    echo "BENCHMARK_EXCLUSION_SOURCE_FAILURE: required source $file is missing" >&2
    exit 1
  fi
  count=$(grep -Fxc "$marker" "$repo/$file" || true)
  count=${count:-0}
  if [[ "$count" != 1 ]]; then
    echo "BENCHMARK_EXCLUSION_SOURCE_FAILURE: $file marker '$marker' count=$count" >&2
    exit 1
  fi
}

# The runner's substring filter is case-sensitive. Keep benchmark names in the
# spelling that -Bench excludes, and pin the two binaries that previously ran
# their benchmarks without any exclusion at all.
require_exact crypto/test/test-db.cpp 'TEST(Cell, BenchSha) {'
require_exact crypto/test/test-db.cpp 'TEST(Cell, BenchShaThreaded) {'
require_exact crypto/test/Ed25519.cpp 'TEST(Crypto, BenchEd25519) {'
require_exact tdutils/test/crypto.cpp 'TEST(Crypto, BenchCrc32c) {'
require_exact CMakeLists.txt 'tos_test(test-ed25519 ${BENCHMARK_FILTER})'
require_exact CMakeLists.txt 'tos_test(test-tdutils ${BENCHMARK_FILTER})'

# Audit the rule, not only today's names: every tracked C/C++ TEST whose name
# contains "bench" in any spelling must contain the exact case-sensitive
# substring "Bench" that the runner's -Bench exclusion recognizes.
bench_tests=$(git -C "$repo" grep -nEi \
  'TEST(_F)?[[:space:]]*\([^,]+,[[:space:]]*[^)]*bench[^)]*\)' \
  -- '*.cpp' '*.cc' '*.cxx' '*.h' '*.hpp' || true)
escaping=$(printf '%s\n' "$bench_tests" | grep -Ev \
  'TEST(_F)?[[:space:]]*\([^,]+,[[:space:]]*[^)]*Bench[^)]*\)' || true)
if [[ -n "$escaping" ]]; then
  printf '%s\n' "$escaping" >&2
  echo "BENCHMARK_EXCLUSION_SOURCE_FAILURE: a TEST name containing bench escapes the case-sensitive -Bench filter" >&2
  exit 1
fi

echo "BENCHMARK_EXCLUSION_SOURCE_OK"
