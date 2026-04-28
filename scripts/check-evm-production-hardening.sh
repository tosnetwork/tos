#!/usr/bin/env bash
# EVM production hardening checks.
#
# MPT permanently removed; this script enforces the no-MPT invariant in
# addition to existing production hardening (debug RPC default-off,
# default-genesis test-account guards, instrumentation flags, blob-
# versioned-hashes strict parsing, hydration corruption fail-closed,
# verified code cache, streaming BoC importer caps, per-IP attribution,
# state-growth invariance harness, etc.).
set -euo pipefail

root="${1:-.}"
core="$root/evm/core"
create_state="$root/crypto/block/create-state.cpp"
pow_giver="$root/evm/contracts/EToSPoWGiver.sol"
pow_giver_fift="$root/crypto/smartcont/etos-pow-givers.fif"
rpc_handlers="$root/evm/rpc/handlers.cpp"
compute_phase="$root/evm/core/compute-phase.cpp"
post_accept="$root/evm/core/post-accept.cpp"
rpc_cache_db="$root/evm/rpc/cache-db.cpp"
validator_download_state="$root/validator/net/download-state.cpp"
validator_token_manager="$root/validator/token-manager.cpp"
cmake_lists="$root/CMakeLists.txt"
harness_paths=(
    "$root/test/conformance/hive/clients/tos/bootstrap-validators.sh"
    "$root/test/conformance/hive/clients/tos/tos.cmd"
    "$root/test/tostester/src/tostester/zerostate.py"
)

# ---------------------------------------------------------------------------
# No-MPT invariant checks.
#
# MPT and the persistent-trie witness path have been permanently removed
# from the EVM workchain. Native cell-state is the only canonical source
# of truth. The six checks below fail CI if any artefact of the old MPT
# regime sneaks back in.
# ---------------------------------------------------------------------------

# Check 1 — MPT source files must NOT exist.
for f in \
    evm/core/mpt-trie.h evm/core/mpt-trie.cpp \
    evm/core/mpt-prover.h evm/core/mpt-prover.cpp \
    evm/core/incremental-trie.h evm/core/incremental-trie.cpp \
    evm/core/state-root.h evm/core/state-root.cpp; do
    if [ -e "$root/$f" ]; then
        echo "evm hardening failed: MPT source file still exists: $f" >&2
        exit 1
    fi
done

# Check 2 — evm/CMakeLists.txt must NOT compile MPT sources.
if rg -n 'mpt-trie|mpt-prover|incremental-trie|state-root\.cpp' "$root/evm/CMakeLists.txt"; then
    echo "evm hardening failed: MPT source still listed in evm/CMakeLists.txt" >&2
    exit 1
fi

# Check 3 — Production source must NOT reference active MPT APIs.
if rg -n 'MptTrie|MptWitness|EthereumTrieWitness|PersistentEthereumTrieWitness|compute_state_root|ethereum_(account|storage)_proof|ethereum_storage_root_hash|trie_witness_root|eth_state_root' "$root/evm" "$root/crypto/block" "$root/validator" "$root/validator-engine"; then
    echo "evm hardening failed: active MPT/witness/root reference remains" >&2
    exit 1
fi

# Check 4 — eth_getProof must NOT have a real handler / enable flag.
# The literal "eth_getProof" stays in evm/rpc/handlers.cpp on purpose: it sits
# in the is_eth_rpc_method allowlist so the dispatcher routes to an explicit
# `-32601 not supported` branch with a canonical message. We reject only real
# implementations / configurable enables.
if rg -n 'handle_get_proof|enable_eth_get_proof|enable_public_evm_getproof' \
        "$root/evm" "$root/validator-engine"; then
    echo "evm hardening failed: eth_getProof handler / enable-flag remains" >&2
    exit 1
fi
# Require the explicit -32601 reject branch with the canonical message.
if ! rg -q 'eth_getProof is not supported' "$root/evm/rpc/handlers.cpp"; then
    echo "evm hardening failed: explicit eth_getProof -32601 reject branch missing in evm/rpc/handlers.cpp" >&2
    exit 1
fi

# Check 5 — cp.new_data must be v6 native-only.
if ! rg -q 'kCpNewDataSchemaVersion\s*=\s*6' "$root/evm/core/cell-codec.h"; then
    echo "evm hardening failed: cp.new_data schema must be native-only v6" >&2
    exit 1
fi

# Check 6 — native commitment helper must exist.
if ! rg -q 'compute_native_evm_state_commitment' "$root/evm/core"; then
    echo "evm hardening failed: native EVM state commitment helper missing" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Existing (non-MPT) production hardening checks.
# ---------------------------------------------------------------------------

if rg -n "test test test test test test test test test test test junk|ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" "$core"; then
    echo "evm production hardening check failed: public test mnemonic/private key must not live under evm/core" >&2
    exit 1
fi

if rg -n 'def_stack_word\("evm-zerostate-accounts-cell ' "$create_state"; then
    echo "evm production hardening check failed: legacy zero-arg EVM zerostate Fift word must not be registered" >&2
    exit 1
fi

if rg -n 'evm-zerostate-accounts-cell|builtin-10-EOAs|built-in 10 EOAs' "${harness_paths[@]}"; then
    echo "evm production hardening check failed: EVM bootstrap harness must not fall back to public test accounts" >&2
    exit 1
fi

hardhat_fixture_hits=$(
    rg -l "test test test test test test test test test test test junk|ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" \
        "$root/doc" "$root/test" "$root/scripts" 2>/dev/null || true
)
for hit in $hardhat_fixture_hits; do
    [ "$hit" = "$root/scripts/check-evm-production-hardening.sh" ] && continue
    if ! rg -q 'TOS_DEVNET_ALLOW_TEST_EVM_ACCOUNTS|devnet fixture|Devnet-Only Hardhat Fixture Accounts' "$hit"; then
        echo "evm production hardening check failed: public Hardhat fixture key must be explicitly devnet-gated in $hit" >&2
        exit 1
    fi
done

if rg -n 'seed[[:space:]]*=[[:space:]]*blockhash\(block\.number - 1\)' "$pow_giver"; then
    echo "evm production hardening check failed: EToSPoWGiver must not rotate seed to parent blockhash alone" >&2
    exit 1
fi

if ! rg -q 'seed[[:space:]]*=[[:space:]]*keccak256\(abi\.encodePacked' "$pow_giver"; then
    echo "evm production hardening check failed: EToSPoWGiver must derive a per-success replay-resistant seed" >&2
    exit 1
fi

if ! rg -q 'metadata\.bytecodeHash=none|metadata hash disabled' "$pow_giver_fift"; then
    echo "evm production hardening check failed: embedded EToSPoWGiver bytecode must document deterministic metadata settings" >&2
    exit 1
fi

if ! rg -q 'TOS_EVM_DEBUG_RPC_TOKEN' "$rpc_handlers"; then
    echo "evm production hardening check failed: debug_rebuildRpcCache must require admin auth even under TOS_ENABLE_EVM_DEBUG_RPC" >&2
    exit 1
fi

if ! rg -q 'debug_traceTransaction requires TOS_EVM_DEBUG_RPC_TOKEN|debug_traceTransaction unauthorized' "$rpc_handlers"; then
    echo "evm production hardening check failed: debug_traceTransaction must require debug RPC auth" >&2
    exit 1
fi

if awk '
  /^#ifdef TOS_ENABLE_EVM_DEBUG_RPC$/ { debug = 1; next }
  /^#endif$/ { debug = 0; next }
  /method == "debug_traceTransaction" \|\|/ { if (!debug) bad = 1 }
  /if \(method == "debug_traceTransaction"\)/ { if (!debug) bad = 1 }
  END { exit bad ? 0 : 1 }
' "$rpc_handlers"; then
    echo "evm production hardening check failed: debug_traceTransaction must be debug-only" >&2
    exit 1
fi

if awk '
  /^#ifdef TOS_ENABLE_EVM_DEBUG_RPC$/ { debug = 1; next }
  /^#endif$/ { debug = 0; next }
  /method == "debug_rebuildRpcCache" \|\|/ { if (!debug) bad = 1 }
  /if \(method == "debug_rebuildRpcCache"\)/ { if (!debug) bad = 1 }
  END { exit bad ? 0 : 1 }
' "$rpc_handlers"; then
    echo "evm production hardening check failed: debug_rebuildRpcCache dispatch must be debug-only" >&2
    exit 1
fi

if rg -n 'estimate_evm_state_size_for_full_root|EVM stateRoot budget exceeded|stateRoot soft budget' "$compute_phase"; then
    echo "evm production hardening check failed: compute phase must not gate stateRoot on full-state budget scans" >&2
    exit 1
fi

if ! rg -q 'kMaxSimulateEmittedBlocks' "$rpc_handlers" ||
   ! rg -q 'simulated block gap too large' "$rpc_handlers" ||
   ! rg -q 'kMaxSimulateResponseBytes' "$rpc_handlers"; then
    echo "evm production hardening check failed: eth_simulateV1 must cap total emitted filler blocks and response bytes" >&2
    exit 1
fi

if ! rg -q 'g_simulate_limiter|kMaxSimulateRequestsPerSec' "$rpc_handlers" ||
   ! rg -q 'g_simulate_inflight|eth_simulateV1 already running' "$rpc_handlers" ||
   ! rg -q 'kMaxSimulateTotalRequestedGas|simulation requested gas budget exceeded' "$rpc_handlers"; then
    echo "evm production hardening check failed: eth_simulateV1 must have method limiter, single-inflight, and requested-gas preflight" >&2
    exit 1
fi

if rg -n 'kMaxSimulateFillerJump[[:space:]]*=[[:space:]]*8192' "$rpc_handlers"; then
    echo "evm production hardening check failed: eth_simulateV1 must not rely on the old per-entry 8192 filler cap" >&2
    exit 1
fi

# Persistent-state downloader must validate total and cumulative size
# before streaming. The download-budget constants and reservation API
# may live either in `validator/net/download-state.cpp` (legacy
# placement), the dedicated `validator/state-download-buffer.cpp`
# library (post-M-01 modularisation), or — after the J2 streaming
# importer — be expressed via the configurable
# `PersistentStateBudgetConfig::max_download_bytes` field.
state_buffer_cpp="$root/validator/state-download-buffer.cpp"
state_buffer_h="$root/validator/state-download-buffer.h"
search_paths=("$validator_download_state")
[ -f "$state_buffer_cpp" ] && search_paths+=("$state_buffer_cpp")
[ -f "$state_buffer_h" ] && search_paths+=("$state_buffer_h")
if ! rg -q 'kMaxPersistentStateDownloadBytes|max_download_bytes' "${search_paths[@]}" 2>/dev/null ||
   ! rg -q 'kMaxPersistentStateHeapBufferBytes|kHeapThreshold' "${search_paths[@]}" 2>/dev/null ||
   ! rg -q 'persistent state stream exceeds advertised size|persistent state too large' "${search_paths[@]}" 2>/dev/null ||
   ! rg -q 'download_started_' "$root/validator/net/download-state.hpp"; then
    echo "evm production hardening check failed: persistent state downloader must validate total and cumulative size before streaming" >&2
    exit 1
fi

if rg -n 'request_total_size\(\);[[:space:]]*got_block_state_part' "$validator_download_state"; then
    echo "evm production hardening check failed: persistent state downloader must not start slices before total size is verified" >&2
    exit 1
fi

if rg -n 'TOS_ALLOW_NPX_SOLC=1' "$cmake_lists"; then
    echo "evm production hardening check failed: CI bytecode equivalence test must not enable npx solc fallback by default" >&2
    exit 1
fi

if ! rg -q 'TOS_SOLC_0_8_26.*CACHE FILEPATH|if\(TOS_SOLC_0_8_26\)' "$cmake_lists"; then
    echo "evm production hardening check failed: bytecode equivalence CTest must require a pinned solc path" >&2
    exit 1
fi

if ! rg -q 'put_incomplete_transaction|put_incomplete_block|has_incomplete_transaction|has_incomplete_block' "$rpc_cache_db" ||
   ! rg -q 'hydrate_evm_rpc_incomplete_indexes_from_cache|has_incomplete_transaction|has_incomplete_block' "$post_accept"; then
    echo "evm production hardening check failed: post-accept incomplete indexes must be durable and restart-hydrated" >&2
    exit 1
fi

if rg -n 'it->second\.promise\.set_value\(gen_token\(size, priority\)\)' "$validator_token_manager"; then
    echo "evm production hardening check failed: TokenManager must wake pending requests with their own size/priority" >&2
    exit 1
fi

# `TOS_EVM_TEST_INSTRUMENTATION` is a test-only macro that exposes lazy-load
# atomic counters. It must never be a `PUBLIC` compile-definition default
# on `evm_workchain` because every production binary linked against
# `evm_workchain` would inherit the instrumentation. The supported pattern
# is the option/guarded form (default OFF) plus a separate test library.
if rg -n '^[^#]*target_compile_definitions\(evm_workchain[[:space:]]+PUBLIC[[:space:]]+TOS_EVM_TEST_INSTRUMENTATION' "$root/evm/CMakeLists.txt" >/dev/null; then
    if ! rg -n 'option\([[:space:]]*TOS_EVM_TEST_INSTRUMENTATION' "$root/evm/CMakeLists.txt" >/dev/null; then
        echo "evm production hardening check failed: TOS_EVM_TEST_INSTRUMENTATION must not be a default-on PUBLIC compile-definition on evm_workchain" >&2
        exit 1
    fi
fi

# Defense in depth: TOS_ENABLE_EVM_DEBUG_RPC unlocks debug_* RPC methods
# (debug_traceTransaction, debug_rebuildRpcCache, ...). It may only be set
# on the test-debug variant library (evm_workchain_test_debug), never on
# the production `evm_workchain` library. The regex requires whitespace
# directly after `evm_workchain`, so `evm_workchain_test` and
# `evm_workchain_test_debug` cannot match (their underscore consumes the
# space slot). The post-filter via the invert grep is a belt-and-braces
# guard in case the regex engine ever loosens. Multiline mode (`rg -U`)
# is required because the production CMakeLists splits multi-flag
# `target_compile_definitions(...)` across several lines.
if rg -n -U 'target_compile_definitions\(\s*evm_workchain[[:space:]]+(PUBLIC|PRIVATE|INTERFACE)[^)]*TOS_ENABLE_EVM_DEBUG_RPC' \
     "$root/evm/CMakeLists.txt" "$root/evm/test/CMakeLists.txt" 2>/dev/null \
     | rg -v 'evm_workchain_test_debug|evm_workchain_test\b' >/dev/null; then
    echo "evm production hardening check failed: TOS_ENABLE_EVM_DEBUG_RPC must only be set on the debug-test library, not on production evm_workchain" >&2
    exit 1
fi

# The eth_simulateV1 stateOverrides parser must reject invalid hex before
# the global EVM mutex is taken. The error strings below are pinned so
# external monitoring can alert on regressions; they are also the contract
# the regression test in evm/test/test-executor.cpp asserts on.
if ! rg -q 'invalid stateOverrides storage slot' "$rpc_handlers" ||
   ! rg -q 'invalid stateOverrides storage value' "$rpc_handlers" ||
   ! rg -q 'invalid stateOverrides code' "$rpc_handlers"; then
    echo "evm production hardening check failed: eth_simulateV1 stateOverrides parser must explicitly reject invalid hex / oversize values before lock" >&2
    exit 1
fi

# K-02 (audit, 2026-04-27 follow-up): every silkworm-driving read-only
# RPC handler that does NOT bind a `WitnessFlatConsistencyContext`
# MUST snapshot `code_root_hash_mismatch_count()` before executing
# silkworm and check the delta after, mapping any increment to a
# JSON-RPC `-32000 corrupt EVM code root`. Without this, a corrupt
# code root surfaces as a confidently-wrong response (empty bytecode,
# falsely-cheap gas estimate, missing logs). The check pins the
# four canonical handlers; future heavy read-only RPC handlers must
# follow the same pattern and add themselves to this list.
for handler in handle_call handle_estimate_gas handle_create_access_list handle_simulate_v1; do
    if ! awk -v h="$handler" '
        $0 ~ "static RpcResult " h "\\(" { in_h = 1 }
        in_h && /code_root_hash_mismatch_count\(\)/ { found = 1 }
        in_h && /^}$/ { in_h = 0 }
        END { exit (found ? 0 : 1) }
    ' "$rpc_handlers"; then
        echo "evm production hardening check failed: $handler must snapshot code_root_hash_mismatch_count before silkworm execution (K-02)" >&2
        exit 1
    fi
done

# K-02 follow-up: `handle_debug_trace_transaction` (admin-gated) ALSO
# runs silkworm against the live state without a verifier context, so
# it must snapshot the mismatch counter too. A regression here would
# let admin-side tracing produce wrong opcode logs on a corrupt code
# root (silkworm sees an empty `ByteView` and records a no-op trace).
if rg -q 'handle_debug_trace_transaction' "$rpc_handlers"; then
    if ! awk '
        /static RpcResult handle_debug_trace_transaction\(/ { in_h = 1 }
        in_h && /code_root_hash_mismatch_count\(\)/ { found = 1 }
        in_h && /^}$/ { in_h = 0 }
        END { exit (found ? 0 : 1) }
    ' "$rpc_handlers"; then
        echo "evm production hardening check failed: handle_debug_trace_transaction must snapshot code_root_hash_mismatch_count (K-02)" >&2
        exit 1
    fi
fi

# H-01 (audit, 2026-04-27): the lazy bytecode decode in
# `CellEvmState::read_code` MUST keccak-hash the decoded bytes and
# compare against the requested code_hash before emplacing into the
# code cache. Anything less reintroduces the
# "code_hash committed but code_root is some other bytecode" execution-
# divergence path the audit calls out. The structural check is split
# in two:
#
#   (1) `CellEvmState::read_code` must funnel its lazy decode through
#       the single chokepoint `decode_and_verify_code_root` (or, in a
#       legacy build, call `decode_evm_bytecode` AND `keccak_code_hash`
#       directly). The chokepoint variant is the canonical post-H-01
#       implementation; without it the helper's verification is
#       bypassed.
#   (2) `decode_and_verify_code_root` itself must compute
#       `keccak_code_hash` of the result of `decode_evm_bytecode` so the
#       chokepoint can never be downgraded to a bare decode.
#
# Both checks live in cell-state.cpp; a regression in either fails
# CI immediately.
if ! awk '
    /silkworm::ByteView CellEvmState::read_code\(/, /^}/ {
        if (/decode_and_verify_code_root\(/) verified = 1
        if (/decode_evm_bytecode\(/) decoded = 1
        if (decoded && /keccak_code_hash\(/) keccak = 1
    }
    END { exit ((verified || keccak) ? 0 : 1) }
' "$root/evm/core/cell-state.cpp"; then
    echo "evm production hardening check failed: CellEvmState::read_code must funnel through decode_and_verify_code_root (or compute keccak_code_hash after decode_evm_bytecode) (H-01 fail-closed code-root invariant)" >&2
    exit 1
fi

# H-01 (audit, 2026-04-27, P0.1): the chokepoint helper itself must
# enforce the invariant — call decode_evm_bytecode AND
# keccak_code_hash. Without this, a future refactor could collapse the
# helper into a bare decode and silently disable the strict-load /
# read_code / update_account_code verification paths.
if ! awk '
    /td::Result<silkworm::Bytes> CellEvmState::decode_and_verify_code_root\(/ { in_h = 1 }
    in_h {
        if (/decode_evm_bytecode\(/) decoded = 1
        if (decoded && /keccak_code_hash\(/) keccak = 1
    }
    in_h && /^}$/ { in_h = 0 }
    END { exit (keccak ? 0 : 1) }
' "$root/evm/core/cell-state.cpp"; then
    echo "evm production hardening check failed: CellEvmState::decode_and_verify_code_root must compute keccak_code_hash on the decode_evm_bytecode result (H-01 chokepoint integrity)" >&2
    exit 1
fi

# H-01 (audit, 2026-04-27, P0.2): the strict-mode `load_from_cell`
# code-cache populate path MUST funnel through
# `decode_and_verify_code_root` BEFORE inserting into `new_code`. The
# previous bug was a bare `decode_evm_bytecode` followed by a direct
# `new_code[acct.code_hash] = ...` assignment with no keccak check, so
# `init.cpp` hydration would happily seed the cache with bytecode whose
# hash disagreed with the account leaf's `code_hash`. The check is
# scoped to the "Strict modes:" section bounded by the
# `code_ = std::move(new_code);` cache-commit point.
if ! awk '
    /StrictValidateNative:/ { in_s = 1 }
    in_s {
        if (/decode_and_verify_code_root\(/) verified = 1
        if (/new_code\.emplace\(|new_code\[/) emplaced = 1
    }
    in_s && /code_ = std::move\(new_code\)/ { in_s = 0 }
    END { exit (verified && emplaced ? 0 : 1) }
' "$root/evm/core/cell-state.cpp"; then
    echo "evm production hardening check failed: CellEvmState::load_from_cell StrictValidateNative path must call decode_and_verify_code_root before populating new_code (H-01 P0.2 fail-closed hydration)" >&2
    exit 1
fi

# Q1 (audit, 2026-04-27, tos16 P0 follow-up — line 818): the canonical
# hydration call site `populate_state_from_shard_accounts` MUST surface
# a structured forensic error on strict-load failure (e.g. a code-root
# / code-hash mismatch surfaced by `decode_and_verify_code_root`):
#
#   (a) Read the descriptive reason via
#       `cs->last_strict_load_failure_reason()` so the offending account
#       address + kind of mismatch reach the operator / monitoring
#       stack. A regression that drops this accessor or stops calling
#       it would revert the surface to a bare boolean failure.
#   (b) Emit a `LOG(ERROR)` carrying the canonical state_root, the
#       reason, and a clear "manual intervention required" sentence so
#       monitoring / Loki rules can match on the line.
#   (c) Flip the sticky `mark_evm_hydration_corrupted(...)` flag so
#       downstream consensus / RPC code refuses to operate. There is no
#       graceful in-process recovery path — operator must restart from
#       a known-good state snapshot or repair canonical state manually.
#
# The check is scoped to the `populate_state_from_shard_accounts` body
# bounded by the `LOG(WARNING) << "evm-workchain: hydrated world state"`
# success line.
if ! awk '
    /size_t populate_state_from_shard_accounts\(/ { in_s = 1 }
    in_s {
        if (/cs->load_from_cell\(state_root,/) saw_load = 1
        if (saw_load && /last_strict_load_failure_reason\(/) reason = 1
        if (saw_load && /mark_evm_hydration_corrupted\(/) marked = 1
        if (saw_load && /state_root_hash/) state_root_logged = 1
    }
    in_s && /hydrated world state from executor cell/ { in_s = 0 }
    END { exit (reason && marked && state_root_logged ? 0 : 1) }
' "$root/evm/core/init.cpp"; then
    echo "evm production hardening check failed: populate_state_from_shard_accounts must call last_strict_load_failure_reason() and mark_evm_hydration_corrupted(state_root, reason) when load_from_cell fails (Q1 tos16 P0 hydration surface)" >&2
    exit 1
fi

# Q1: the structured-error helper itself must build the canonical
# "EVM canonical hydration FAILED: state_root=... reason=..." text so
# operators / monitoring rules can match on a stable string. A
# regression that strips state_root / reason / "manual intervention
# required" from the LOG(ERROR) breaks the contract.
if ! rg -q 'EVM canonical hydration FAILED: state_root=' "$root/evm/core/init.cpp"; then
    echo "evm production hardening check failed: init.cpp must emit canonical 'EVM canonical hydration FAILED: state_root=' LOG(ERROR) on hydration corruption (Q1 forensic surface)" >&2
    exit 1
fi
if ! rg -q 'Manual intervention required' "$root/evm/core/init.cpp"; then
    echo "evm production hardening check failed: init.cpp must instruct 'Manual intervention required' in the hydration corruption LOG(ERROR) (Q1 forensic surface)" >&2
    exit 1
fi
if ! rg -q 'std::atomic<bool> g_evm_hydration_corrupted' "$root/evm/core/init.cpp"; then
    echo "evm production hardening check failed: init.cpp must declare g_evm_hydration_corrupted atomic flag (Q1 sticky corruption flag)" >&2
    exit 1
fi
if ! rg -q 'bool evm_hydration_corrupted\(\) noexcept' "$root/evm/core/init.h"; then
    echo "evm production hardening check failed: init.h must export evm_hydration_corrupted() so consensus / RPC entry points can refuse to operate (Q1 sticky corruption flag)" >&2
    exit 1
fi
if ! rg -q 'last_strict_load_failure_reason' "$root/evm/core/cell-state.h"; then
    echo "evm production hardening check failed: cell-state.h must export last_strict_load_failure_reason() (Q1 strict-load failure accessor)" >&2
    exit 1
fi

# The expensive EVM compute-phase invariant must NOT be gated on
# `#ifndef NDEBUG`. Public testnet builds (release WITHOUT NDEBUG) would
# otherwise reintroduce a per-tx full StrictRecursive validation. Use an
# explicit opt-in CMake option (`TOS_EVM_STRICT_COMPUTE_INVARIANTS`).
if rg -n '#ifndef NDEBUG' "$compute_phase" >/dev/null 2>&1; then
    echo "evm production hardening check failed: expensive EVM compute invariant must use TOS_EVM_STRICT_COMPUTE_INVARIANTS, not NDEBUG" >&2
    exit 1
fi

# L-02 (c): TOS_EVM_STRICT_COMPUTE_INVARIANTS must default OFF. The
# expensive per-tx StrictRecursive invariant check is opt-in only.
if rg -n 'option\(TOS_EVM_STRICT_COMPUTE_INVARIANTS[^)]*ON\b' "$root/evm/CMakeLists.txt" >/dev/null; then
    echo "evm production hardening check failed: TOS_EVM_STRICT_COMPUTE_INVARIANTS must default OFF" >&2
    exit 1
fi

# L-02 (d): TOS_ALLOW_NPX_SOLC=1 must NOT be set in CI release scripts.
# Operators may still set it locally for development. Be tolerant if
# the .github/ or scripts/ci/ directories don't exist.
if [ -d "$root/.github" ] || [ -d "$root/scripts/ci" ]; then
    npx_hits=""
    for ci_dir in "$root/.github" "$root/scripts/ci"; do
        [ -d "$ci_dir" ] || continue
        hits=$(rg -n 'TOS_ALLOW_NPX_SOLC[[:space:]]*=[[:space:]]*1' "$ci_dir" 2>/dev/null \
                 | rg -v 'allowed-locally|local-dev' || true)
        if [ -n "$hits" ]; then
            npx_hits+="$hits"$'\n'
        fi
    done
    if [ -n "$npx_hits" ]; then
        echo "evm production hardening check failed: TOS_ALLOW_NPX_SOLC=1 must not be set in CI release profile" >&2
        echo "$npx_hits" >&2
        exit 1
    fi
fi

# L-02 (e): debug RPC dispatcher + allowlist MUST be wrapped in
# TOS_ENABLE_EVM_DEBUG_RPC. The earlier checks (lines ~74-94) already
# verify per-method gating; this is a coarser sanity check that the
# macro itself is referenced at all.
if ! rg -n '#ifdef TOS_ENABLE_EVM_DEBUG_RPC' "$rpc_handlers" >/dev/null; then
    echo "evm production hardening check failed: debug RPC must be guarded by TOS_ENABLE_EVM_DEBUG_RPC" >&2
    exit 1
fi

# L-02 (f): default EvmRpcProfile MUST be ValidatorMinimal (M-03
# hand-off). A regression that lowers the default to FollowerPublic
# silently re-exposes heavy read-only RPC on every validator.
if ! rg -n 'g_evm_rpc_profile\{[^}]*ValidatorMinimal' "$rpc_handlers" >/dev/null; then
    echo "evm production hardening check failed: default EvmRpcProfile must be ValidatorMinimal" >&2
    exit 1
fi

# L-02 (f-bis): every read-only EVM RPC handler that runs silkworm
# against the live state MUST be in the heavy-readonly profile gate.
# A regression that adds a new heavy RPC handler without listing it
# alongside `eth_call` re-opens the validator to public swarm load.
# The check pins the canonical list (eth_call / eth_estimateGas /
# eth_createAccessList / eth_simulateV1) — all four must appear in
# the same gating clause inside `handle_eth_rpc`.
if ! rg -q 'method == "eth_call".*method == "eth_estimateGas"' "$rpc_handlers" \
        --multiline 2>/dev/null && \
   ! rg -q -U 'method == "eth_call" \|\| method == "eth_estimateGas" \|\|\s*method == "eth_createAccessList" \|\| method == "eth_simulateV1"' "$rpc_handlers" 2>/dev/null; then
    echo "evm production hardening check failed: heavy read-only profile gate must list eth_call / eth_estimateGas / eth_createAccessList / eth_simulateV1 together" >&2
    exit 1
fi

# M-02: AdminLocal EVM RPC profile must be refused on a non-loopback
# listener unless `--allow-remote-admin-rpc` is set AND an API key is
# configured. The listener-layer hardening lives in
# `validator-engine/json-rpc-server.cpp` (`refusing AdminLocal ...`
# error strings emitted from `JsonRpcServer::listen`). A regression
# that silently re-applies `set_evm_rpc_profile(AdminLocal)` on a
# remote address would re-expose the higher 30M gas cap and
# (when compiled in) debug methods to public clients.
json_rpc_server_cpp="$root/validator-engine/json-rpc-server.cpp"
if ! grep -q "refusing AdminLocal" "$json_rpc_server_cpp"; then
    echo "evm production hardening check failed: missing AdminLocal non-loopback hardening in $json_rpc_server_cpp" >&2
    exit 1
fi
if ! grep -q "allow_remote_admin_rpc" "$json_rpc_server_cpp"; then
    echo "evm production hardening check failed: AdminLocal remote override flag (allow_remote_admin_rpc) missing in $json_rpc_server_cpp" >&2
    exit 1
fi

# Production EVM call-object parser must be the strict variant. The
# legacy `parse_call_object` accepted hex/decimal inconsistencies that
# the strict parser rejects up-front (audit J1). A regression that
# revives the loose parser would re-introduce divergent gas/value
# accounting on the public eth_* surface.
if ! rg -q 'parse_call_object_strict' "$rpc_handlers"; then
    echo "evm production hardening check failed: handle_call must use parse_call_object_strict" >&2
    exit 1
fi
if rg -q '^\s*static silkworm::Transaction parse_call_object\b' "$rpc_handlers"; then
    echo "evm production hardening check failed: legacy parse_call_object must be deleted" >&2
    exit 1
fi

# K1 streaming BoC importer must drive the OnDisk persistent-state
# parse path. A regression that re-introduces a one-shot
# vm::std_boc_deserialize call against the mmap'd tempfile would
# reintroduce the file-size peak resident memory the importer was
# designed to remove.
if ! rg -q 'std_boc_deserialize_from_file_bounded' "$root/validator/downloaders/download-state.cpp"; then
    echo "evm production hardening check failed: streaming BoC importer must drive OnDisk parse" >&2
    exit 1
fi

# J2 zero-state OnDisk path must also drive the streaming BoC importer.
# The mmap stays for the SHA256 file_hash check, but after that gate
# passes the actual BoC parse must go through the bounded streaming
# importer so peak resident memory is bounded by `max_resident_bytes`,
# NOT by the zero-state file size. (See wait-block-state.cpp
# got_state_from_net_budgeted OnDisk branch.)
if ! rg -q 'std_boc_deserialize_from_file_bounded' "$root/validator/downloaders/wait-block-state.cpp"; then
    echo "evm production hardening check failed: zero-state OnDisk path must drive streaming BoC importer" >&2
    exit 1
fi

# Coverage-guided libFuzzer harness for the BoC streaming importer must
# exist and be gated behind TOS_BUILD_LIBFUZZER. The test-boc-libfuzzer
# driver is the post-MPT survivor; trie-shaped fuzz harnesses were
# removed alongside MPT itself.
if [ ! -f "$root/evm/test/test-boc-libfuzzer.cpp" ]; then
    echo "evm production hardening check failed: test-boc-libfuzzer.cpp must exist for coverage-guided BoC fuzz coverage" >&2
    exit 1
fi
if ! rg -q 'TOS_BUILD_LIBFUZZER' "$root/evm/test/CMakeLists.txt"; then
    echo "evm production hardening check failed: evm/test/CMakeLists.txt must gate the libFuzzer harness behind TOS_BUILD_LIBFUZZER" >&2
    exit 1
fi
if ! rg -q 'TOS_BUILD_LIBFUZZER' "$cmake_lists"; then
    echo "evm production hardening check failed: root CMakeLists.txt must declare option(TOS_BUILD_LIBFUZZER ...) so the libFuzzer harness can be enabled in CI" >&2
    exit 1
fi

if [[ "${TOS_CHECK_ETOS_GIVER_BYTECODE:-0}" == "1" ]]; then
    if ! command -v node >/dev/null 2>&1; then
        echo "evm production hardening check failed: node is required for EToSPoWGiver bytecode equivalence check" >&2
        exit 1
    fi
    node - "$root" <<'NODE'
const fs = require('fs');
const path = require('path');
const cp = require('child_process');

const root = process.argv[2];
const sourcePath = path.join(root, 'evm/contracts/EToSPoWGiver.sol');
const fiftPath = path.join(root, 'crypto/smartcont/etos-pow-givers.fif');
const source = fs.readFileSync(sourcePath, 'utf8');
const input = {
  language: 'Solidity',
  sources: {'evm/contracts/EToSPoWGiver.sol': {content: source}},
  settings: {
    optimizer: {enabled: true, runs: 200},
    metadata: {bytecodeHash: 'none'},
    outputSelection: {'*': {'*': ['evm.deployedBytecode.object']}}
  }
};

let output = null;
let compiler = null;
const choices = [];
if (process.env.TOS_SOLC_0_8_26) {
  choices.push([process.env.TOS_SOLC_0_8_26, ['--standard-json']]);
}
if (process.env.HOME) {
  choices.push([path.join(process.env.HOME, '.solcx/solc-v0.8.26'), ['--standard-json']]);
}
if (process.env.TOS_ALLOW_NPX_SOLC === '1') {
  choices.push(['npx', ['--yes', 'solc@0.8.26', '--standard-json']]);
}
try {
  const version = cp.execFileSync('solc', ['--version'], {
    encoding: 'utf8',
    timeout: 10000,
    stdio: ['ignore', 'pipe', 'ignore'],
  });
  if (/Version:\s+0\.8\.26\+|^0\.8\.26\+/.test(version)) {
    choices.push(['solc', ['--standard-json']]);
  }
} catch (_) {
  // solc is optional; pinned local and npx fallbacks are tried above.
}
for (const choice of choices) {
  try {
    output = cp.execFileSync(choice[0], choice[1], {
      input: JSON.stringify(input),
      encoding: 'utf8',
      maxBuffer: 20 * 1024 * 1024,
      timeout: 30000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    compiler = [choice[0], ...choice[1]].join(' ');
    break;
  } catch (_) {
    // Try the next compiler source.
  }
}
if (!output) {
  console.error('evm production hardening check failed: cannot run pinned solc 0.8.26 standard-json (set TOS_SOLC_0_8_26, install $HOME/.solcx/solc-v0.8.26, install solc 0.8.26, or set TOS_ALLOW_NPX_SOLC=1 for local npx fallback)');
  process.exit(1);
}

const json = JSON.parse(output.slice(output.indexOf('{')));
if (json.errors) {
  const errors = json.errors.filter((e) => e.severity === 'error');
  if (errors.length !== 0) {
    console.error(errors.map((e) => e.formattedMessage || e.message).join('\n'));
    process.exit(1);
  }
}
const compiled = json.contracts['evm/contracts/EToSPoWGiver.sol'].EToSPoWGiver.evm.deployedBytecode.object;
const fift = fs.readFileSync(fiftPath, 'utf8');
const match = fift.match(/"([0-9a-f]+)" x>B constant etos-giver-code/);
if (!match) {
  console.error('evm production hardening check failed: etos-giver-code literal not found');
  process.exit(1);
}
if (match[1] !== compiled) {
  console.error(`evm production hardening check failed: embedded EToSPoWGiver bytecode does not match source (${compiler})`);
  console.error(`compiled bytes=${compiled.length / 2}, embedded bytes=${match[1].length / 2}`);
  process.exit(1);
}
console.log(`EToSPoWGiver bytecode matches source (${compiled.length / 2} bytes, ${compiler})`);
NODE
fi

# N-1 (audit, follower-public RPC hardening): the in-process per-IP
# rate limiter must be present in the EVM RPC dispatcher. The gate is
# strictly stronger than relying on a reverse proxy alone — it survives
# a misconfigured proxy and stops a single attacker from draining the
# global per-method buckets for everyone else.
if ! rg -q 'consume_per_ip_token|g_per_ip_buckets' "$rpc_handlers"; then
    echo "evm production hardening check failed: per-IP rate limiter must be present in EVM RPC dispatcher" >&2
    exit 1
fi

# Confirm the dispatcher itself consults the gate (not just defines
# the helper). Awk walks the body of `handle_eth_rpc` and asserts a
# `consume_per_ip_token(` call appears before the closing brace.
if ! awk '
    /std::optional<RpcResult> handle_eth_rpc\(/ { in_h = 1 }
    in_h && /consume_per_ip_token\(/ { found = 1 }
    in_h && /^}$/ { in_h = 0 }
    END { exit (found ? 0 : 1) }
' "$rpc_handlers"; then
    echo "evm production hardening check failed: handle_eth_rpc dispatcher must call consume_per_ip_token before per-method limiters" >&2
    exit 1
fi

# tos16 H-02 + H-03: bounded streaming BoC importer must (a) treat
# StreamingBocImportOptions::max_cells == 0 as the safe default rather
# than unlimited, (b) carry an explicit max_scaffolding_bytes field,
# (c) wrap every O(cell_count) vector allocation in try/catch returning
# the canonical "cannot allocate BoC import scaffolding" error so
# std::bad_alloc cannot escape to the actor boundary, and (d) the
# OnDisk persistent-state parse path must fail closed when the file
# size exceeds max_returned_dag_bytes_per_parse without true streaming.
boc_h="$root/crypto/vm/boc.h"
boc_cpp="$root/crypto/vm/boc.cpp"
download_state_cpp="$root/validator/downloaders/download-state.cpp"
state_buffer_h="$root/validator/state-download-buffer.h"

if ! rg -q 'kDefaultStreamingBocMaxCells' "$boc_h"; then
    echo "evm production hardening check failed: kDefaultStreamingBocMaxCells must be declared in crypto/vm/boc.h" >&2
    exit 1
fi

if ! rg -q 'max_cells = kDefaultStreamingBocMaxCells' "$boc_h"; then
    echo "evm production hardening check failed: StreamingBocImportOptions::max_cells must default to kDefaultStreamingBocMaxCells (NOT 0/unlimited)" >&2
    exit 1
fi

if ! rg -q 'max_scaffolding_bytes' "$boc_h"; then
    echo "evm production hardening check failed: StreamingBocImportOptions::max_scaffolding_bytes field must be present" >&2
    exit 1
fi

if ! rg -q 'BoC scaffolding budget exceeded' "$boc_cpp"; then
    echo "evm production hardening check failed: std_boc_deserialize_from_file_bounded must enforce max_scaffolding_bytes" >&2
    exit 1
fi

scaffolding_catch_hits=$(rg -c 'cannot allocate BoC import scaffolding' "$boc_cpp" || true)
if [ -z "$scaffolding_catch_hits" ] || [ "$scaffolding_catch_hits" -lt 4 ]; then
    echo "evm production hardening check failed: vector allocations in std_boc_deserialize_from_file_bounded must be wrapped in try/catch returning 'cannot allocate BoC import scaffolding' (need >=4 hits, got ${scaffolding_catch_hits:-0})" >&2
    exit 1
fi

if ! rg -q 'max_returned_dag_bytes_per_parse' "$state_buffer_h"; then
    echo "evm production hardening check failed: PersistentStateBudgetConfig::max_returned_dag_bytes_per_parse must be present" >&2
    exit 1
fi

if ! rg -q 'enable_true_cell_db_streaming_import' "$state_buffer_h"; then
    echo "evm production hardening check failed: PersistentStateBudgetConfig::enable_true_cell_db_streaming_import flag must be present" >&2
    exit 1
fi

if ! rg -q 'enable CellDb streaming importer' "$download_state_cpp"; then
    echo "evm production hardening check failed: download-state.cpp must fail closed on oversize states without true streaming importer" >&2
    exit 1
fi

if ! rg -q 'max_cells_per_parse' "$download_state_cpp"; then
    echo "evm production hardening check failed: download-state.cpp must forward max_cells_per_parse into vm::StreamingBocImportOptions" >&2
    exit 1
fi

# M-01 (audit, 2026-04-27): the JSON-RPC server's per-IP rate-limit
# attribution MUST be keyed off the real TCP peer IP captured at accept
# time, not off forgeable X-Forwarded-For / X-Real-IP headers. The
# helper `JsonRpcServer::resolve_source_ip` is the single chokepoint;
# trust_proxy_headers + the trusted-proxy allow-list MUST be wired
# through the JsonRpcServer Options. A regression that re-enables
# unconditional XFF / XRI honour would let a direct public client
# rotate per-IP buckets at will.
if ! rg -q 'resolve_source_ip' "$json_rpc_server_cpp"; then
    echo "evm production hardening check failed: JsonRpcServer::resolve_source_ip helper missing — per-IP attribution must use a single chokepoint (M-01)" >&2
    exit 1
fi
if ! rg -q 'trust_proxy_headers' "$json_rpc_server_cpp"; then
    echo "evm production hardening check failed: trust_proxy_headers wiring missing in $json_rpc_server_cpp (M-01)" >&2
    exit 1
fi
if ! rg -q 'peer_ip\(\)|peer_ip\b' "$json_rpc_server_cpp"; then
    echo "evm production hardening check failed: JsonRpcServer must consult HttpRequest::peer_ip() for per-IP attribution (M-01)" >&2
    exit 1
fi
# The shared "unknown" bucket sentinel must collapse empty
# attributions instead of bypassing the gate.
if ! rg -q '"unknown"' "$json_rpc_server_cpp"; then
    echo "evm production hardening check failed: JsonRpcServer must collapse empty peer attribution to the shared \"unknown\" bucket (M-01)" >&2
    exit 1
fi

# M-02 (audit, 2026-04-27): parse_call_object_strict MUST consult the
# strict blobVersionedHashes parser. The lax parser silently dropped
# malformed entries; a regression that revives it would re-introduce
# silent transaction-type downgrade on a bad call object.
if ! rg -q 'parse_blob_versioned_hashes_strict' "$rpc_handlers"; then
    echo "evm production hardening check failed: parse_blob_versioned_hashes_strict must exist (M-02)" >&2
    exit 1
fi
# The legacy lax helper must NOT be called from the strict call-object
# parser. We scan the strict parser's body for any reference to the
# legacy name; the strict variant is allowed because it carries the
# `_strict` suffix.
if awk '
    /^static td::Result<silkworm::Transaction>$/ { peek = 1; next }
    peek && /parse_call_object_strict\(/ { in_h = 1; peek = 0; next }
    peek { peek = 0 }
    in_h {
        if (/parse_blob_versioned_hashes\(/) bad = 1
    }
    in_h && /^}$/ { in_h = 0 }
    END { exit (bad ? 0 : 1) }
' "$rpc_handlers"; then
    echo "evm production hardening check failed: parse_call_object_strict must NOT call the lax parse_blob_versioned_hashes (M-02)" >&2
    exit 1
fi

# Q-2 (audit, 2026-04-27, no-MPT regime): under the prior MPT design the
# state-growth invariant required four explicit OFF/ON-ratio benchmarks
# threaded through `serialize_trie_witness_to_cell` /
# `WitnessFlatConsistencyContext`. With MPT permanently removed those
# witness primitives are gone, so the invariant is now upheld two ways:
#
#   (a) `CellEvmState::load_from_cell` defaults to `TrustedLazy` mode,
#       which by construction binds only the account-dictionary root
#       and never walks the full state — see evm/core/cell-state.cpp
#       (W2-A `enum class CellStateLoadMode`).
#   (b) At least one no-MPT-regime test must continue to demonstrate
#       behavioural state-growth invariance end-to-end (i.e. a tx
#       against an N-account world still bounded in time).
#
# The check below only enforces (b): a single named anchor test,
# preserving the "single transfer doesn't full-walk N accounts"
# observable. The strict 4-test ratio harness is retired with the
# witness primitives that supported it.
test_executor_cpp="$root/evm/test/test-executor.cpp"
if ! rg -q 'void test_large_state_simple_transfer_no_full_walk\(\)' "$test_executor_cpp"; then
    echo "evm production hardening check failed: test_large_state_simple_transfer_no_full_walk must exist in $test_executor_cpp (Q-2 no-MPT state-growth invariance anchor)" >&2
    exit 1
fi
# Belt-and-braces: the load-mode default in cell-state.h must remain
# TrustedLazy. A regression that flipped it to a strict-walk mode would
# re-introduce the O(N) per-tx hydration cost that the no-MPT plan
# explicitly eliminated.
if ! rg -q 'CellStateLoadMode\s+mode\s*=\s*CellStateLoadMode::TrustedLazy' "$root/evm/core/cell-state.h"; then
    echo "evm production hardening check failed: CellEvmState::load_from_cell default mode must be CellStateLoadMode::TrustedLazy (Q-2 no-MPT state-growth invariance by construction)" >&2
    exit 1
fi

echo "evm production hardening check passed"
