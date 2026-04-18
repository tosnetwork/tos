#!/usr/bin/env bash
# =============================================================================
# run-rpc-compat-local.sh — minimal local harness for the rpc-compat fixtures.
# =============================================================================
#
# Replays each *.io fixture from execution-apis/tests/<method>/*.io against a
# running endpoint (default: the container started by Dockerfile.proxy) and
# tallies pass/fail.  This is NOT the real Hive simulator — it's a lightweight
# pre-flight that exercises the same fixture set, so we can iterate on the
# tos.cmd / mapper.jq pipeline without the 30-min Hive build cycle.
#
# Usage:
#   RPC_URL=http://127.0.0.1:18546 bash run-rpc-compat-local.sh
#   bash run-rpc-compat-local.sh                # uses default RPC_URL
#   bash run-rpc-compat-local.sh eth_chainId    # filter to one method
#
# Comparison policy mirrors hive/rpc-compat:
#   - exact match on result   -> PASS
#   - both sides report error -> PASS (error code/message ignored)
#   - mismatch                -> FAIL (with diff)
# =============================================================================

set -euo pipefail

RPC_URL="${RPC_URL:-http://127.0.0.1:18546}"
TESTS_ROOT="${TESTS_ROOT:-test/conformance/execution-apis/tests}"
FILTER="${1:-}"

if [ ! -d "$TESTS_ROOT" ]; then
    echo "ERROR: $TESTS_ROOT does not exist (run from repo root)" >&2
    exit 2
fi

if ! command -v jq >/dev/null; then
    echo "ERROR: jq is required" >&2
    exit 2
fi

pass=0
fail=0
skip=0
fail_names=()

for io in $(find "$TESTS_ROOT" -name '*.io' | sort); do
    method=$(basename "$(dirname "$io")")
    name=$(basename "$io" .io)
    if [ -n "$FILTER" ] && [ "$method" != "$FILTER" ]; then
        continue
    fi

    # Skip multi-roundtrip fixtures (anything with more than one >> line).
    req_count=$(grep -c '^>>' "$io" || true)
    if [ "$req_count" != "1" ]; then
        skip=$((skip + 1))
        continue
    fi

    req=$(grep '^>>' "$io" | head -1 | sed 's/^>> //')
    expected=$(grep '^<<' "$io" | head -1 | sed 's/^<< //')

    actual=$(curl -sS --max-time 10 -X POST -H 'Content-Type: application/json' \
                  --data "$req" "$RPC_URL" || echo "{}")

    # Normalise JSON for comparison.
    actual_n=$(printf '%s' "$actual"   | jq -cS . 2>/dev/null || echo NULL)
    expected_n=$(printf '%s' "$expected" | jq -cS . 2>/dev/null || echo NULL)

    actual_result=$(printf '%s'   | jq -r '.result // empty' <<<"$actual_n" 2>/dev/null || true)
    expected_result=$(printf '%s' | jq -r '.result // empty' <<<"$expected_n" 2>/dev/null || true)
    actual_err=$(printf '%s'   | jq -r '.error.code // empty' <<<"$actual_n" 2>/dev/null || true)
    expected_err=$(printf '%s' | jq -r '.error.code // empty' <<<"$expected_n" 2>/dev/null || true)

    verdict="FAIL"
    if [ "$actual_n" = "$expected_n" ]; then
        verdict="PASS"
    elif [ -n "$actual_err" ] && [ -n "$expected_err" ]; then
        verdict="PASS (both errored)"
    elif [ "$actual_result" = "$expected_result" ] && [ -n "$expected_result" ]; then
        verdict="PASS (result match, ids differ)"
    fi

    if [[ "$verdict" == PASS* ]]; then
        pass=$((pass + 1))
        printf '  ok   %s/%s — %s\n' "$method" "$name" "$verdict"
    else
        fail=$((fail + 1))
        fail_names+=("$method/$name")
        printf '  FAIL %s/%s\n         expected=%s\n         actual  =%s\n' \
            "$method" "$name" "$expected_n" "$actual_n"
    fi
done

echo
echo "============================================================"
printf 'PASS=%d  FAIL=%d  SKIP=%d (multi-roundtrip)\n' "$pass" "$fail" "$skip"
echo "============================================================"
if [ "$fail" -gt 0 ]; then
    echo "First 10 failures:"
    printf '  - %s\n' "${fail_names[@]:0:10}"
fi
