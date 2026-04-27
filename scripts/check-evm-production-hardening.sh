#!/usr/bin/env bash
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

witness_line=$(rg -n 'trie_witness_ready' "$compute_phase" | head -n1 | cut -d: -f1 || true)
exec_line=$(rg -n 'execute_evm_transaction\(decoded\.txn' "$compute_phase" | head -n1 | cut -d: -f1 || true)
if [ -z "$witness_line" ] || [ -z "$exec_line" ] || [ "$witness_line" -ge "$exec_line" ]; then
    echo "evm production hardening check failed: persistent trie witness must be checked before transaction execution" >&2
    exit 1
fi
prevalidate_line=$(rg -n 'prevalidate_evm_transaction_admission\(.*decoded\.txn|prevalidate_evm_transaction_admission\(' "$compute_phase" | head -n1 | cut -d: -f1 || true)
if [ -z "$prevalidate_line" ] || [ "$prevalidate_line" -ge "$witness_line" ]; then
    echo "evm production hardening check failed: cheap EVM tx prevalidation must run before trie witness checks" >&2
    exit 1
fi

if rg -n 'estimate_evm_state_size_for_full_root|EVM stateRoot budget exceeded|stateRoot soft budget' "$compute_phase"; then
    echo "evm production hardening check failed: compute phase must not gate stateRoot on full-state budget scans" >&2
    exit 1
fi

if ! rg -q 'kCpNewDataSchemaVersion[[:space:]]*=[[:space:]]*5' "$root/evm/core/cell-codec.h" ||
   ! rg -q 'trie_witness_root_out|PersistentEthereumTrieWitness|has_trie_witness' "$root/evm/core/cell-codec.cpp" "$root/evm/core/cell-codec.h"; then
    echo "evm production hardening check failed: cp.new_data v5 must carry persistent trie witness" >&2
    exit 1
fi

if ! rg -q 'class MptTrie|serialize_to_cell|proof\(' "$root/evm/core/mpt-trie.h" ||
   ! rg -q 'rlp_cache|load_from_cell|upsert_hashed|erase_hashed' "$root/evm/core/mpt-trie.cpp"; then
    echo "evm production hardening check failed: persistent Ethereum MPT witness backend is missing" >&2
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

if ! rg -q 'ethereum_account_proof|ethereum_storage_proof|ethereum_storage_root_hash' "$rpc_handlers"; then
    echo "evm production hardening check failed: eth_getProof must use persistent trie witness proofs" >&2
    exit 1
fi

if ! rg -q 'g_public_getproof_enabled[[:space:]]*=[[:space:]]*true' "$rpc_handlers"; then
    echo "evm production hardening check failed: eth_getProof should default on after persistent proof backend is enabled" >&2
    exit 1
fi

if rg -n 'generate_mpt_proof\(|mpt_root\(|compute_storage_root_for_account|For non-target accounts we use kEmptyRoot|other_addr == addr\) their_storage_hash = storage_hash' "$rpc_handlers"; then
    echo "evm production hardening check failed: eth_getProof must not rebuild or approximate tries per request" >&2
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

# Compute hot path must not strict-validate the persistent trie witness.
# The lazy-load contract is: validate the witness root cell shallowly and
# bind it to the executor; any mutation/proof path then decodes account /
# storage trie nodes path-bounded. A regression that re-introduces a
# strict recursive walk on the consensus path would re-establish the
# O(global accounts) DoS / liveness ceiling P0 was meant to remove.
#
# We accept any of the recognised tokens for the strict-recursive variant
# (current planned identifier is `TrieWitnessLoadMode::StrictRecursive`,
# but earlier drafts used `StrictRecursiveValidation` and a function name
# of `load_trie_witness_strict`). The pattern is intentionally tolerant
# so the check works whether or not the P0 rename has fully landed.
if [ -f "$compute_phase" ]; then
    if rg -n 'load_trie_witness_from_cell\([^)]*Strict|load_trie_witness_strict\(|TrieWitnessLoadMode::Strict' "$compute_phase" >/dev/null; then
        echo "evm production hardening check failed: compute hot path must not strict-recursively validate trie witness (use TrustedShallow + path-bounded decode)" >&2
        exit 1
    fi
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

# Production sources (evm/core, evm/rpc) must NOT call the legacy unsafe
# MPT/CellState helpers without the explicit `_unsafe_for_*` / `_safe`
# suffix. The safe variants surface corrupt-witness errors as `td::Status`;
# the unsafe variants either lazy-mutate `touched_storage_tries_` under a
# const path (P0.1 H-01) or swallow corrupt-witness errors as kEmptyRoot.
# Tests are exempt — they are allowed to keep using the *_unsafe_for_tests_only
# variants for ergonomics. The check is intentionally tolerant: it scans
# only for raw call-site shapes, then drops anything containing the safe
# or unsafe-for-tests-only suffixes.
unsafe_hits=$(
    rg -n '(ethereum_storage_root_hash|ethereum_account_proof|ethereum_storage_proof)\(' \
        "$root/evm/core" "$root/evm/rpc" \
        --type-add 'cpp:*.{c,cc,cpp,h,hpp}' --type cpp \
        -g '!evm/test/**' \
        -g '!**/*test*' 2>/dev/null \
    | rg -v '_unsafe_for_tests_only|_unsafe_for_execution_cache|_safe' \
    | rg -v '^[[:space:]]*//' \
    || true
)
if [ -n "$unsafe_hits" ]; then
    echo "evm production hardening check failed: unsafe MPT/CellState API in production path:" >&2
    echo "$unsafe_hits" >&2
    exit 1
fi

# L-01 (audit, 2026-04-27): the `*_unsafe_for_tests_only` API surface MUST
# be wrapped in `#ifdef TOS_EVM_TEST_INSTRUMENTATION` so production builds
# of `evm_workchain` (which do not define the macro) do not export the
# symbols. The check below uses awk to track which lines fall inside an
# `#ifdef TOS_EVM_TEST_INSTRUMENTATION ... #endif` block; any
# `*_unsafe_for_tests_only(...)` call site / declaration outside that
# region (and outside test-* sources) is a regression.
unsafe_l01_offenders=""
for f in $(find "$root/evm/core" "$root/evm/rpc" \
                -type f \( -name '*.cpp' -o -name '*.h' -o -name '*.hpp' \) 2>/dev/null); do
    case "$f" in
        */test-*)
            continue
            ;;
    esac
    out=$(awk -v file="$f" '
        BEGIN { depth = 0 }
        /^[[:space:]]*#[[:space:]]*ifdef[[:space:]]+TOS_EVM_TEST_INSTRUMENTATION([[:space:]]|$)/ { depth++; next }
        /^[[:space:]]*#[[:space:]]*if[[:space:]]+defined\([[:space:]]*TOS_EVM_TEST_INSTRUMENTATION[[:space:]]*\)/ { depth++; next }
        /^[[:space:]]*#[[:space:]]*if(n)?def[[:space:]]+/ { if (depth > 0) depth++; next }
        /^[[:space:]]*#[[:space:]]*if[[:space:]]/ { if (depth > 0) depth++; next }
        /^[[:space:]]*#[[:space:]]*endif/ { if (depth > 0) depth--; next }
        /unsafe_for_tests_only\(/ {
            if (depth == 0 && $0 !~ /^[[:space:]]*\/\//) {
                printf("%s:%d:%s\n", file, NR, $0)
            }
        }
    ' "$f")
    if [ -n "$out" ]; then
        unsafe_l01_offenders="${unsafe_l01_offenders}${out}
"
    fi
done
if [ -n "$unsafe_l01_offenders" ]; then
    echo "evm production hardening check failed: unsafe API used outside test instrumentation" >&2
    printf '%s' "$unsafe_l01_offenders" >&2
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
    /Strict modes:/ { in_s = 1 }
    in_s {
        if (/decode_and_verify_code_root\(/) verified = 1
        if (/new_code\.emplace\(|new_code\[/) emplaced = 1
    }
    in_s && /code_ = std::move\(new_code\)/ { in_s = 0 }
    END { exit (verified && emplaced ? 0 : 1) }
' "$root/evm/core/cell-state.cpp"; then
    echo "evm production hardening check failed: CellEvmState::load_from_cell strict-mode path must call decode_and_verify_code_root before populating new_code (H-01 P0.2 fail-closed hydration)" >&2
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

# L-02 (a): RPC handlers MUST NOT call the unsafe-for-tests-only
# MPT / CellState helpers. The safe variants surface corrupt-witness
# errors as `td::Status`; the unsafe variants either lazy-mutate
# `touched_storage_tries_` under a const path or swallow corrupt
# witnesses. The check is scoped to `evm/rpc/` because untrusted JSON
# inputs land there; `evm/core` legitimately defines wrapper
# functions whose own name carries the `*_unsafe_for_tests_only`
# suffix (those wrappers are themselves the test-only API and are
# already covered by the broader `evm/core` audit on lines ~244-258).
unsafe_rpc_hits=$(
    rg -n '(proof_unsafe_for_tests_only|root_hash_unsafe_for_tests_only|ethereum_(account|storage)_proof_unsafe_for_tests_only|ethereum_storage_root_hash_unsafe_for_execution_cache)\(' \
        "$root/evm/rpc" \
        --type-add 'cpp:*.{c,cc,cpp,h,hpp}' --type cpp \
        -g '!evm/test/**' -g '!**/*test*' 2>/dev/null \
    | rg -v '^[^:]+:[0-9]+:[[:space:]]*//' \
    || true
)
if [ -n "$unsafe_rpc_hits" ]; then
    echo "evm production hardening check failed: unsafe MPT/CellState API used in production path" >&2
    echo "$unsafe_rpc_hits" >&2
    exit 1
fi

# L-02 (b): the eth_getProof storage-key parser MUST NOT silently
# `continue` past invalid hex keys (L-01 hardening). Any regression
# that re-introduces `continue` after `hex_len > 64` or inside the
# eth_getProof loop is a strict-validation regression.
if rg -n 'eth_getProof.*continue|hex_len > 64.*continue' "$rpc_handlers" >/dev/null; then
    echo "evm production hardening check failed: eth_getProof storage key parser must not silently continue past invalid input" >&2
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
# silently re-exposes heavy read-only RPC + eth_getProof on every
# validator.
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
# remote address would re-expose the higher 30M gas cap, eth_getProof
# and (when compiled in) debug methods to public clients.
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

# Audit checklist (lines 1097-1112): the BoC streaming importer must
# carry randomized fuzz coverage for code-root / storage-trie corruption
# alongside the MPT primitives. A regression that drops the BoC drivers
# from test-mpt-fuzz reverts the fuzz contract from "no crash on any
# random byte stream into the OnDisk parse path" back to "crash space
# unmeasured".
if ! rg -q 'fuzz_boc_streaming_importer_round_trip' "$root/evm/test/test-mpt-fuzz.cpp"; then
    echo "evm production hardening check failed: test-mpt-fuzz must carry BoC streaming importer fuzz drivers" >&2
    exit 1
fi
if ! rg -q 'fuzz_boc_streaming_truncated_input' "$root/evm/test/test-mpt-fuzz.cpp"; then
    echo "evm production hardening check failed: test-mpt-fuzz must carry truncated-input BoC fuzz driver" >&2
    exit 1
fi

# Audit checklist (lines 1097-1112): the deterministic Mulberry32 fuzz
# drivers in test-mpt-fuzz.cpp explore a fixed seeded space; coverage-
# guided libFuzzer harnesses explore byte-level mutation patterns the
# static seed list cannot anticipate. Both surfaces are required for
# public-readiness fuzz coverage. A regression that drops the
# coverage-guided harnesses reverts the contract from "no crash on any
# coverage-discovered input" back to "crash space unmeasured beyond
# the seed corpus".
if [ ! -f "$root/evm/test/test-mpt-libfuzzer.cpp" ] || [ ! -f "$root/evm/test/test-boc-libfuzzer.cpp" ]; then
    echo "evm production hardening check failed: libFuzzer harnesses (test-mpt-libfuzzer.cpp / test-boc-libfuzzer.cpp) must exist for coverage-guided fuzz coverage" >&2
    exit 1
fi
if ! rg -q 'TOS_BUILD_LIBFUZZER' "$root/evm/test/CMakeLists.txt"; then
    echo "evm production hardening check failed: evm/test/CMakeLists.txt must gate the libFuzzer harnesses behind TOS_BUILD_LIBFUZZER" >&2
    exit 1
fi
if ! rg -q 'TOS_BUILD_LIBFUZZER' "$cmake_lists"; then
    echo "evm production hardening check failed: root CMakeLists.txt must declare option(TOS_BUILD_LIBFUZZER ...) so the libFuzzer harnesses can be enabled in CI" >&2
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

echo "evm production hardening check passed"
