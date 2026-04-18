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
# Comparison policy mirrors hive/rpc-compat (verified against
# https://github.com/ethereum/hive/blob/master/simulators/ethereum/rpc-compat/main.go):
#   - exact match on result        -> PASS
#   - both sides report error      -> PASS (code/message ignored)
#   - fixture has `// speconly:`   -> PASS if response shape matches
#                                     (recursive type-check à la hive's
#                                     checkJSONStructure)
#   - mismatch                     -> FAIL (with diff)
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
if ! command -v python3 >/dev/null; then
    echo "ERROR: python3 is required (for speconly schema check)" >&2
    exit 2
fi

# -----------------------------------------------------------------------------
# speconly schema check — equivalent to hive's checkJSONStructure: every key
# present in `expected` must exist in `actual` with the same JSON kind, and
# vice versa (no unexpected keys).  Recurses into objects/arrays.  Implemented
# in inline Python because jq's recursion-by-key is tedious and Python is
# already required for the proxy / chain.rlp helpers.
# -----------------------------------------------------------------------------
shape_check() {
    local expected="$1"
    local actual="$2"
    python3 - "$expected" "$actual" <<'PYEOF' 2>/dev/null
import json, sys
exp = json.loads(sys.argv[1])
act = json.loads(sys.argv[2])

def kind(v):
    if v is None:        return "null"
    if v is True or v is False: return "bool"
    if isinstance(v, (int, float)): return "number"
    if isinstance(v, str): return "string"
    if isinstance(v, list): return "array"
    if isinstance(v, dict): return "object"
    return "unknown"

def check(e, a, path):
    errs = []
    if kind(e) != kind(a):
        # null vs object/array tolerated only when expected is null and actual is null/empty
        errs.append(f"{path}: type mismatch (expected {kind(e)}, got {kind(a)})")
        return errs
    if isinstance(e, list):
        # hive only verifies that actual is also an array
        return errs
    if isinstance(e, dict):
        for k, v in e.items():
            sub = path + "." + k if path != "." else "." + k
            if k not in a:
                errs.append(f"{sub}: missing key")
                continue
            errs += check(v, a[k], sub)
        # unexpected keys
        for k in a.keys():
            if k not in e:
                errs.append(("." + k if path == "." else path + "." + k) + ": unexpected key")
    return errs

errs = check(exp.get("result"), act.get("result"), ".")
sys.exit(0 if not errs else 1)
PYEOF
}

pass=0
fail=0
skip=0
speconly_pass=0
fail_names=()

# Verdict for a single (request, expected, actual) triple.
verdict_for_pair() {
    local expected_n="$1"
    local actual_n="$2"
    local speconly="$3"

    local actual_err
    local expected_err
    actual_err=$(jq -r '.error.code // empty' <<<"$actual_n" 2>/dev/null || true)
    expected_err=$(jq -r '.error.code // empty' <<<"$expected_n" 2>/dev/null || true)
    local actual_result expected_result
    actual_result=$(jq -r '.result // empty' <<<"$actual_n" 2>/dev/null || true)
    expected_result=$(jq -r '.result // empty' <<<"$expected_n" 2>/dev/null || true)

    if [ "$actual_n" = "$expected_n" ]; then
        printf 'PASS\n'; return
    fi
    if [ -n "$actual_err" ] && [ -n "$expected_err" ]; then
        printf 'PASS (both errored)\n'; return
    fi
    if [ "$actual_result" = "$expected_result" ] && [ -n "$expected_result" ]; then
        printf 'PASS (result match, ids differ)\n'; return
    fi
    if [ "$speconly" = "1" ] && [ -z "$actual_err" ]; then
        if shape_check "$expected_n" "$actual_n"; then
            printf 'PASS (speconly: shape match)\n'; return
        fi
    fi
    printf 'FAIL\n'
}

for io in $(find "$TESTS_ROOT" -name '*.io' | sort); do
    method=$(basename "$(dirname "$io")")
    name=$(basename "$io" .io)
    if [ -n "$FILTER" ] && [ -n "${1:-}" ] && [ "$method" != "$FILTER" ]; then
        continue
    fi

    speconly=0
    if grep -q '^// speconly:' "$io"; then
        speconly=1
    fi

    # Collect all roundtrips: paired ">> req" / "<< expected" lines, in order.
    mapfile -t reqs < <(grep '^>>' "$io" | sed 's/^>> //')
    mapfile -t exps < <(grep '^<<' "$io" | sed 's/^<< //')
    if [ "${#reqs[@]}" -ne "${#exps[@]}" ]; then
        # Malformed: unequal request/expected count.
        skip=$((skip + 1))
        continue
    fi
    if [ "${#reqs[@]}" -eq 0 ]; then
        skip=$((skip + 1))
        continue
    fi

    overall_verdict="PASS"
    last_actual_n=""
    last_expected_n=""
    speconly_match_used=0
    for ((rt = 0; rt < ${#reqs[@]}; rt++)); do
        req="${reqs[$rt]}"
        expected="${exps[$rt]}"
        actual=$(curl -sS --max-time 10 -X POST -H 'Content-Type: application/json' \
                      --data "$req" "$RPC_URL" || echo "{}")
        actual_n=$(printf '%s' "$actual"   | jq -cS . 2>/dev/null || echo NULL)
        expected_n=$(printf '%s' "$expected" | jq -cS . 2>/dev/null || echo NULL)
        v=$(verdict_for_pair "$expected_n" "$actual_n" "$speconly")
        last_actual_n="$actual_n"
        last_expected_n="$expected_n"
        if [[ "$v" == FAIL ]]; then
            overall_verdict="FAIL"
            break
        fi
        if [[ "$v" == "PASS (speconly: shape match)" ]]; then
            speconly_match_used=1
        fi
        # Carry the last successful verdict forward so the print line
        # at the bottom mentions the relevant tag.
        overall_verdict="$v"
    done

    if [[ "$overall_verdict" == PASS* ]]; then
        pass=$((pass + 1))
        if [ "$speconly_match_used" = "1" ]; then
            speconly_pass=$((speconly_pass + 1))
        fi
        suffix=""
        if [ "${#reqs[@]}" -gt 1 ]; then
            suffix=" [${#reqs[@]} roundtrips]"
        fi
        printf '  ok   %s/%s — %s%s\n' "$method" "$name" "$overall_verdict" "$suffix"
    else
        fail=$((fail + 1))
        fail_names+=("$method/$name")
        printf '  FAIL %s/%s\n         expected=%s\n         actual  =%s\n' \
            "$method" "$name" "$last_expected_n" "$last_actual_n"
    fi
done

echo
echo "============================================================"
printf 'PASS=%d  FAIL=%d  SKIP=%d (malformed)   [speconly: %d]\n' \
    "$pass" "$fail" "$skip" "$speconly_pass"
echo "============================================================"
if [ "$fail" -gt 0 ]; then
    echo "First 10 failures:"
    printf '  - %s\n' "${fail_names[@]:0:10}"
fi
