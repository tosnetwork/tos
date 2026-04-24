#!/usr/bin/env bash
#
# UNO MineUno end-to-end integration test.
#
# Exercises the FULL C++ compute-phase apply pipeline against a REAL
# Plonky3 STARK proof produced live by the in-tree Rust prover FFI.
#
# What this script validates (end-to-end; no mocks on the crypto path):
#
#   1. `uno_mine_uno_prove` FFI produces a valid proof + 96-byte PI
#      blob from a deterministic witness.
#   2. The C++ MineUno BoC codec round-trips: encode_mine_uno_to_boc →
#      decode_mine_uno_bytes → identical fields, identical proof blob.
#   3. `uno_workchain::apply_mine_uno`:
#        - runs `verify_mine_uno_chain_checks` (epoch, remaining,
#          halving reward, conservation),
#        - calls `uno_mine_uno_verify` on the real proof bytes,
#        - mutates FakeUnoState: epoch += 1, remaining -= 50 UNO,
#          appends PI.output_cm to commitments, accumulates a filter
#          tag.
#   4. Replay attack: resubmitting the same tx against the mutated
#      state returns `VerifyResult::EpochRaceDetected` and leaves
#      state unchanged.
#
# Why not spin up a full wc=2 node?
#   A full-node e2e needs collator + RPC + genesis spin-up (~minutes
#   of setup and a heavy fixture tree). We instead drive the exact
#   same compute-phase entry point (`apply_mine_uno`) that the block
#   producer calls per tx. The crypto is NOT mocked — the STARK proof
#   is generated live in-process. A full-network e2e can be layered on
#   top of this once `tosctl uno mine` + a UNO RPC endpoint are both
#   live against a long-lived test network.
#
# Usage:
#   bash uno/test/integration/test-mine-uno-end-to-end.sh
#
# Wall clock: ~22-30 s (dominated by the single STARK prove).
# Exit code:  0 on PASS, non-zero on FAIL.

set -euo pipefail

# Resolve repo root relative to this script so the test is runnable
# from any cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

BUILD_DIR="${UNO_BUILD_DIR:-${REPO_ROOT}/build}"
BIN="${BUILD_DIR}/uno/test/test-mine-uno-apply-e2e"

echo "============================================================"
echo "UNO MineUno end-to-end integration test"
echo "============================================================"
echo "Repo root: ${REPO_ROOT}"
echo "Build dir: ${BUILD_DIR}"
echo

# Build the driver binary if missing. This is a guard rail — the
# binary is one `cmake --build` away once CMake has been configured.
if [ ! -x "${BIN}" ]; then
    echo "[build] ${BIN} not found — building..."
    if ! command -v cmake >/dev/null 2>&1; then
        echo "SKIP: cmake not on PATH and ${BIN} is not pre-built."
        echo "      Build manually: cmake --build ${BUILD_DIR} \\"
        echo "                          --target test-mine-uno-apply-e2e -j 64"
        exit 0
    fi
    if [ ! -d "${BUILD_DIR}" ]; then
        echo "SKIP: ${BUILD_DIR} does not exist. Configure the CMake build first:"
        echo "      cmake -S ${REPO_ROOT} -B ${BUILD_DIR} -G Ninja -DCMAKE_BUILD_TYPE=Release"
        exit 0
    fi
    cmake --build "${BUILD_DIR}" --target test-mine-uno-apply-e2e -j 64
fi

if [ ! -x "${BIN}" ]; then
    echo "FAIL: ${BIN} is still missing after build attempt." >&2
    exit 1
fi

# Run the full apply pipeline.
echo "[run] ${BIN}"
echo
"${BIN}"
rc=$?

echo
if [ "${rc}" -eq 0 ]; then
    echo "============================================================"
    echo "PASS: MineUno end-to-end apply pipeline green."
    echo "============================================================"
else
    echo "FAIL: test-mine-uno-apply-e2e exited with code ${rc}" >&2
fi

exit "${rc}"
