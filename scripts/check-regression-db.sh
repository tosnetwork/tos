#!/usr/bin/env bash
# Runs the recorded answers, and requires the record to name only tests that exist.
#
# `REGRESSION_VERIFY` compares a test's output against a hash in
# `test/regression-tests.ans` -- but only when the binary is given `--regression`.
# Without it the macro logs a line and returns success, so for as long as no job passed
# the flag, every one of these tests reported on nothing. The record drifted
# accordingly: four of its entries named tests that had been deleted, and four more
# held hashes from before the contracts they cover were rewritten.
#
# Both halves are checked here. Running the tests catches an answer that changed;
# comparing the names catches a test that went away, which is the failure the record
# cannot report by itself, because a hash nobody asks about never disagrees with
# anything.
set -euo pipefail

root="${1:-.}"
build="${2:-$root/build}"
answers="$root/test/regression-tests.ans"
failed=0

# The binaries whose tests record an answer. A binary added here without its tests in
# the record simply records them on the first run; a binary left out is the way a test
# stops being checked, so the list is compared against the record below.
binaries="test-fift test-cells test-vm test-smartcont"

for binary in $binaries; do
  if [ ! -x "$build/$binary" ]; then
    echo "regression check failed: $build/$binary is not built" >&2
    failed=1
    continue
  fi
done
[ "$failed" -eq 0 ] || exit 1

# A copy, so a run cannot quietly record a new answer over a changed one.
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
cp "$answers" "$scratch/answers.ans"
# The cache beside the record holds the full output behind each hash, which is what turns a
# disagreement from two hex strings into something readable. It is a local artifact, not a
# tracked one, so a fresh checkout has none and a copy that assumes otherwise fails the
# whole check before a single test has run. Copy it when it is there; the test framework
# creates an empty one when it is not.
if [ -d "$root/test/regression-tests.cache" ]; then
  cp -r "$root/test/regression-tests.cache" "$scratch/answers.cache"
fi

for binary in $binaries; do
  if ! "$build/$binary" --regression "$scratch/answers.ans" >"$scratch/$binary.log" 2>&1; then
    echo "regression check failed: $binary" >&2
    grep -oE "Test [A-Za-z_0-9]+ changed: \[[^]]*\]\[[^]]*\]" "$scratch/$binary.log" >&2 || true
    failed=1
  fi
done

if ! cmp -s "$answers" "$scratch/answers.ans"; then
  echo "regression check failed: the run recorded an answer that was not in the record" >&2
  diff -u "$answers" "$scratch/answers.ans" >&2 || true
  failed=1
fi

# The record must name exactly the tests that record an answer.
#
# Running the tests catches an answer that changed. It cannot catch an answer that is no
# longer asked for: a test that was deleted, or one that still runs with its
# `REGRESSION_VERIFY` removed, leaves a hash in the record that nothing ever compares,
# and the run above stays green either way.
#
# So the same tests are run once more against an empty record, which makes every call to
# `REGRESSION_VERIFY` write its name instead of comparing. What that produces is the set
# of tests that actually verify something, and it has to be the set the record holds.
# Each binary records into a record of its own, so two binaries claiming the same test
# name are two lines here rather than one. A shared record would have let the second one
# merely agree with the first, and a test produced by two programs is a test whose answer
# depends on which program ran.
: >"$scratch/verifying.all"
for binary in $binaries; do
  fresh="$scratch/fresh-$binary.ans"
  printf 'abce\n' >"$fresh"
  if ! "$build/$binary" --regression "$fresh" >/dev/null 2>&1; then
    echo "regression check failed: $binary could not record into an empty record" >&2
    failed=1
    continue
  fi
  tail -n +2 "$fresh" | awk -v b="$binary" '{print $1"\t"b}' >>"$scratch/verifying.all"
done

sort "$scratch/verifying.all" -o "$scratch/verifying.all"
while read -r duplicate; do
  [ -n "$duplicate" ] || continue
  echo "regression check failed: ${duplicate%_default} records an answer from more than one program" >&2
  failed=1
done < <(awk -F'\t' '{if ($1 == last) print $1; last = $1}' "$scratch/verifying.all" | sort -u)

tail -n +2 "$answers" | awk '{print $1}' | sort -u >"$scratch/recorded"
awk -F'\t' '{print $1}' "$scratch/verifying.all" | sort -u >"$scratch/verifying"

while read -r name; do
  [ -n "$name" ] || continue
  echo "regression check failed: ${name%_default} has an answer and verifies nothing" >&2
  failed=1
done < <(comm -23 "$scratch/recorded" "$scratch/verifying")

while read -r name; do
  [ -n "$name" ] || continue
  echo "regression check failed: ${name%_default} verifies an answer the record does not hold" >&2
  failed=1
done < <(comm -13 "$scratch/recorded" "$scratch/verifying")

if [ "$failed" -eq 0 ]; then
  echo "every recorded answer is verified by a test, and every test still gives it"
fi
exit "$failed"
