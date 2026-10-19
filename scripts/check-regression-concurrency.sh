#!/usr/bin/env bash
set -euo pipefail

root=${1:-.}
build=${2:-$root/build}
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

if ! command -v python3 >/dev/null 2>&1; then
  echo "REGRESSION_CONCURRENCY_FAILURE: python3 is required for the lock-identity gate" >&2
  exit 1
fi

for binary in test-fift test-cells; do
  if [[ ! -x "$build/$binary" ]]; then
    echo "REGRESSION_CONCURRENCY_FAILURE: $binary is not built" >&2
    exit 1
  fi
done

# Hold the answer-file sidecar with the same POSIX record lock FileFd uses.
# A writer with an explicit cache must still block here: cache location is not
# part of the identity of the answer file being protected.
printf 'abce\n' >"$scratch/lock-probe.ans"
python3 - "$scratch/lock-probe.ans.lock" "$scratch/lock-ready" "$scratch/lock-release" <<'PY' &
import fcntl
import os
import sys
import time

lock_path, ready_path, release_path = sys.argv[1:]
with open(lock_path, "a+b") as lock_file:
    fcntl.lockf(lock_file, fcntl.LOCK_EX)
    open(ready_path, "w").close()
    while not os.path.exists(release_path):
        time.sleep(0.01)
PY
lock_pid=$!
for _ in $(seq 1 500); do
  [[ -f "$scratch/lock-ready" ]] && break
  sleep 0.01
done
if [[ ! -f "$scratch/lock-ready" ]]; then
  kill "$lock_pid" 2>/dev/null || true
  wait "$lock_pid" 2>/dev/null || true
  echo "REGRESSION_CONCURRENCY_FAILURE: could not acquire the answer-file probe lock" >&2
  exit 1
fi

"$build/test-cells" --regression "$scratch/lock-probe.ans" \
  --regression-cache "$scratch/different-cache-location" --filter -Bench >/dev/null 2>&1 &
probe_writer_pid=$!
writer_bypassed=0
for _ in $(seq 1 500); do
  if ! kill -0 "$probe_writer_pid" 2>/dev/null; then
    writer_bypassed=1
    break
  fi
  sleep 0.01
done
touch "$scratch/lock-release"
wait "$lock_pid"
if [[ "$writer_bypassed" -eq 1 ]]; then
  wait "$probe_writer_pid" || true
  echo "REGRESSION_CONCURRENCY_FAILURE: explicit-cache writer bypassed the answer-file lock" >&2
  exit 1
fi
wait "$probe_writer_pid"

for binary in test-fift test-cells; do
  printf 'abce\n' >"$scratch/expected-$binary.ans"
  "$build/$binary" --regression "$scratch/expected-$binary.ans" \
    --regression-cache "$scratch/cache-expected-$binary" --filter -Bench >/dev/null 2>&1
done

# A missing answer file is the normal first-run state and must be created in
# full. An existing malformed file is not equivalent to absence and must fail
# loudly instead of being overwritten.
missing_answers="$scratch/missing.ans"
if ! "$build/test-cells" --regression "$missing_answers" --regression-cache "$scratch/cache-missing" \
    --filter -Bench >/dev/null 2>&1; then
  echo "REGRESSION_CONCURRENCY_FAILURE: first writer rejected a missing answer file" >&2
  exit 1
fi
if [[ ! -f "$missing_answers" ]] || ! cmp -s "$missing_answers" "$scratch/expected-test-cells.ans"; then
  echo "REGRESSION_CONCURRENCY_FAILURE: first writer did not create a complete answer file" >&2
  exit 1
fi

printf 'not-a-regression-database\n' >"$scratch/corrupt.ans"
if "$build/test-cells" --regression "$scratch/corrupt.ans" --regression-cache "$scratch/cache-corrupt" \
    --filter -Bench >"$scratch/corrupt.log" 2>&1; then
  echo "REGRESSION_CONCURRENCY_FAILURE: corrupt answer file was accepted" >&2
  exit 1
fi
if ! grep -q 'Regression database .* is corrupt' "$scratch/corrupt.log"; then
  echo "REGRESSION_CONCURRENCY_FAILURE: corrupt answer file failed without naming corruption" >&2
  cat "$scratch/corrupt.log" >&2
  exit 1
fi

{ tail -n +2 "$scratch/expected-test-fift.ans"; tail -n +2 "$scratch/expected-test-cells.ans"; } \
  | sort >"$scratch/expected"

printf 'abce\n' >"$scratch/shared.ans"
"$build/test-fift" --regression "$scratch/shared.ans" --regression-cache "$scratch/cache-shared-fift" \
  --filter -Bench >"$scratch/fift.log" 2>&1 &
fift_pid=$!

# Wait until the slow writer has loaded the empty record and begun executing.
# The fast writer then necessarily starts from the same dirty snapshot; without
# the locked reload-and-merge, whichever process renames last drops the other.
for _ in $(seq 1 200); do
  if grep -q '^Running test ' "$scratch/fift.log"; then
    break
  fi
  if ! kill -0 "$fift_pid" 2>/dev/null; then
    wait "$fift_pid" || true
    echo "REGRESSION_CONCURRENCY_FAILURE: test-fift exited before the concurrent writer started" >&2
    exit 1
  fi
  sleep 0.01
done
if ! grep -q '^Running test ' "$scratch/fift.log"; then
  kill "$fift_pid" 2>/dev/null || true
  wait "$fift_pid" 2>/dev/null || true
  echo "REGRESSION_CONCURRENCY_FAILURE: test-fift did not reach its first test" >&2
  exit 1
fi

# Deliberately use the default cache for the second writer. The lock must be
# keyed by the shared answer file, not by these two different cache locations.
"$build/test-cells" --regression "$scratch/shared.ans" --filter -Bench >"$scratch/cells.log" 2>&1 &
cells_pid=$!
wait "$cells_pid"
wait "$fift_pid"

tail -n +2 "$scratch/shared.ans" | sort >"$scratch/actual"
if ! cmp -s "$scratch/expected" "$scratch/actual"; then
  echo "REGRESSION_CONCURRENCY_FAILURE: concurrent dirty writers did not preserve both answer sets" >&2
  diff -u "$scratch/expected" "$scratch/actual" >&2 || true
  exit 1
fi

echo "REGRESSION_CONCURRENCY_OK: concurrent dirty writers preserved both answer sets"
