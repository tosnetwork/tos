/*
    EVM Workchain — module initialisation implementation.

    Registers the native EVM workchain engine with the host-chain
    WorkchainExecutionRegistry.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm/core/init.h"
#include "evm/core/workchain.h"

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/workchain-execution-dispatch.h"
#include "evm/core/cell-codec.h"
#include "evm/core/dispatch-engine.h"
#include "evm/rpc/cache-codec.h"
#include "evm/rpc/cache-db.h"
#include "evm/core/compute-phase.h"
#include "evm/core/native-commitment.h"
#include "evm/core/post-accept.h"
#include "evm/core/state.h"
#include "evm/core/cell-state.h"

#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/dict.h"

#include <silkworm/core/types/account.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/execution/precompile.hpp>
#include <silkworm/core/protocol/param.hpp>

#include <ethash/keccak.hpp>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>

#include "td/utils/logging.h"

namespace evm_workchain {

// Runtime-overridable chain id. Stored as a plain `uint64_t` (not atomic)
// because writes happen exactly once during process init, before any RPC
// thread spins up. Reads are unsynchronised but safe in that ordering —
// see the contract on `set_evm_chain_id` in `evm-workchain.h`.
static uint64_t g_evm_chain_id = kEvmChainId;

// Audit Q1 (tos16 P0 follow-up): canonical hydration corruption flag.
//
// `populate_state_from_shard_accounts` is called from a `size_t`-returning
// surface (collator / validate-query / RPC startup) that has no place to
// thread a structured `td::Status` back to the actor manager. When the
// strict cell-state load fails because of a code-root / code-hash
// mismatch (or any other structural violation surfaced by
// `CellEvmState::last_strict_load_failure_reason()`), we:
//
//   1. Emit a `LOG(ERROR)` carrying the canonical state_root, the
//      offending account / code_hash, and the helper's reason text. The
//      string is stable so external monitoring / Loki alerts can match
//      on `evm canonical hydration FAILED`.
//   2. Set `g_evm_hydration_corrupted` to true; readers consult this
//      flag at every consensus / RPC entry point that requires a
//      hydrated state and refuse to enter normal operation. The flag is
//      sticky across the process lifetime — the operator must restart
//      from a known-good state snapshot or repair the canonical state
//      manually.
//   3. Stash the most recent reason into `g_evm_hydration_failure_reason`
//      under `g_evm_hydration_failure_reason_mutex` so any later
//      observer (RPC / health endpoint / log scraper) can read the
//      same canonical text without racing the LOG(ERROR) call.
//
// This is the documented `init.cpp` constructor / OnceFlag fallback
// path: the surrounding caller chain is `void` (and from
// `validator-engine::init_evm_workchain`), so we cannot graceful-
// propagate a Status; instead we burn the flag and let downstream
// consensus / RPC code refuse to operate on a corrupt state.
static std::atomic<bool> g_evm_hydration_corrupted{false};
static std::mutex g_evm_hydration_failure_reason_mutex;
static std::string g_evm_hydration_failure_reason;

bool evm_hydration_corrupted() noexcept {
    return g_evm_hydration_corrupted.load(std::memory_order_acquire);
}

std::string evm_hydration_failure_reason() {
    std::lock_guard<std::mutex> lock(g_evm_hydration_failure_reason_mutex);
    return g_evm_hydration_failure_reason;
}

void reset_evm_hydration_corruption_for_test() noexcept {
    g_evm_hydration_corrupted.store(false, std::memory_order_release);
    std::lock_guard<std::mutex> lock(g_evm_hydration_failure_reason_mutex);
    g_evm_hydration_failure_reason.clear();
}

namespace {

// Audit Q1: lower-case 0x-prefixed hex of an EVM 32-byte hash. Local to
// this translation unit; the cell-state.cpp helper of the same shape
// lives in an anonymous namespace and is not re-exported.
std::string format_evm_hash_hex(const evmc::bytes32& hash) {
    static constexpr char kHexDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(2 + 64);
    out.append("0x");
    for (auto b : hash.bytes) {
        out.push_back(kHexDigits[(b >> 4) & 0x0F]);
        out.push_back(kHexDigits[b & 0x0F]);
    }
    return out;
}

// Audit Q1: mark the global EVM state as corrupt so downstream consensus
// / RPC entry points refuse to operate. Captures the canonical state
// root + the cell-state-supplied reason for forensic logging.
void mark_evm_hydration_corrupted(const evmc::bytes32& state_root_hash,
                                   td::Slice reason) {
    g_evm_hydration_corrupted.store(true, std::memory_order_release);
    std::string formatted;
    formatted.reserve(64 + reason.size());
    formatted.append("EVM canonical hydration FAILED: state_root=");
    formatted.append(format_evm_hash_hex(state_root_hash));
    formatted.append(" reason=");
    formatted.append(reason.data(), reason.size());
    formatted.append(
        "; node refuses normal operation. Restart from a known-good state "
        "snapshot or repair the canonical state. Manual intervention required.");
    {
        std::lock_guard<std::mutex> lock(g_evm_hydration_failure_reason_mutex);
        g_evm_hydration_failure_reason = formatted;
    }
    LOG(ERROR) << formatted;
}

}  // namespace

uint64_t current_evm_chain_id() noexcept {
    return g_evm_chain_id;
}

void set_evm_chain_id(uint64_t chain_id) noexcept {
    g_evm_chain_id = chain_id;
}

static std::unique_ptr<EvmState> g_evm_state;

EvmState& global_evm_state() {
    return *g_evm_state;
}

namespace {

#ifdef TOS_DEVNET_ALLOW_TEST_EVM_ACCOUNTS

struct TestAccount {
    const char* address;   // 40 hex chars, no 0x prefix
};

// Devnet-only public Ethereum tutorial accounts #0..#9. Production builds
// never compile this table or seed these accounts. Private keys intentionally
// do not live under evm/core; tests that need signing use their own fixtures.
constexpr TestAccount kTestAccounts[] = {
    {"f39Fd6e51aad88F6F4ce6aB8827279cffFb92266"},
    {"70997970C51812dc3A010C7d01b50e0d17dc79C8"},
    {"3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"},
    {"90F79bf6EB2c4f870365E785982E1f101E93b906"},
    {"15d34AAf54267DB7D7c367839AAf71A00a2C6A65"},
    {"9965507D1a55bcC2695C58ba16FB37d819B0A4dc"},
    {"976EA74026E726554dB657fA54763abd0C3a0aa9"},
    {"14dC79964da2C08b23698B3D3cc7Ca32193d9955"},
    {"23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f"},
    {"a0Ee7A142d267C1f36714E4a8F75612F20a79720"},
};

constexpr uint64_t kSeedAmountETos = 10000000;  // 10 M eTOS per account (10 × 10 M = 100 M total)

#endif  // TOS_DEVNET_ALLOW_TEST_EVM_ACCOUNTS

#ifdef TOS_DEVNET_ALLOW_TEST_EVM_ACCOUNTS
bool parse_hex_address(const char* hex, evmc::address& out) {
    for (int i = 0; i < 20; ++i) {
        unsigned x;
        if (std::sscanf(hex + i * 2, "%2x", &x) != 1) return false;
        out.bytes[i] = static_cast<uint8_t>(x);
    }
    return true;
}

void seed_test_accounts(EvmState& state) {
    // Idempotency: if account #0 already has any state (from a previous run
    // that was persisted), assume seeding has been done and skip. This makes
    // the function safe to call on every node startup, even after users have
    // moved test funds around.
    evmc::address first_addr{};
    parse_hex_address(kTestAccounts[0].address, first_addr);
    if (state.read_account(first_addr).has_value()) {
        LOG(WARNING) << "evm-workchain: test accounts already seeded, skipping";
        return;
    }

    // kSeedAmountETos eTOS = kSeedAmountETos × 10^18 wei
    intx::uint256 amount{kSeedAmountETos};
    for (int i = 0; i < 18; ++i) amount *= intx::uint256{10};

    LOG(WARNING) << "evm-workchain: seeding " << std::size(kTestAccounts)
                 << " devnet test accounts with "
                 << kSeedAmountETos << " eTOS each";

    for (const auto& a : kTestAccounts) {
        evmc::address addr{};
        if (!parse_hex_address(a.address, addr)) continue;
        state.seed_account(addr, amount, /*nonce=*/0);
        LOG(WARNING) << "evm-workchain:   0x" << a.address;
    }
}
#endif  // TOS_DEVNET_ALLOW_TEST_EVM_ACCOUNTS

}  // anonymous namespace

// =============================================================================
// CANCUN PRE-FORK PREP (Category E, doc/evm-workchain-known-divergences.md)
//
// These helpers prepare the production runtime for the EVM chain config
// profile selected by the active workchain descriptor. They are safe to call
// at every node startup; once Cancun/Pectra rules are active, the relevant
// predeploys must already be present in state.
//
// Added in clearly-marked section to coordinate with parallel work on
// genesis-alloc helpers (Agent K) — DO NOT collapse into init_evm_workchain
// flow; new helpers are appended here, then dispatched from the bottom of
// init_evm_workchain.
// =============================================================================

namespace {

// EIP-4788 deployed runtime bytecode at kBeaconRootsAddress.
// Source: https://eips.ethereum.org/EIPS/eip-4788 §"Deployment".
// This is the *runtime* bytecode (not the deployer init code) — exactly
// what every Cancun-spec mainnet client has at 0x000F…Beac02. Length: 97
// bytes (194 hex chars). The on-chain deployment transaction's `input`
// field is `0x60618060095f395ff3` + this runtime; the 9-byte init prefix
// CODECOPYs the rest into memory and RETURNs it. Logic: when called with
// sender == kSystemAddress it stores the calldata to ring-buffer slot
// (timestamp % HISTORY_BUFFER_LENGTH); otherwise it serves a parent-
// beacon-root lookup keyed by the calldata timestamp.
// HISTORY_BUFFER_LENGTH = 8191 = 0x1FFF.
constexpr const char* kEip4788Bytecode =
    "3373fffffffffffffffffffffffffffffffffffffffe14604d57602036146024575f5ffd5b"
    "5f35801560495762001fff810690815414603c575f5ffd5b62001fff01545f5260205ff35b"
    "5f5ffd5b62001fff42064281555f359062001fff015500";

// EIP-2935 deployed runtime bytecode at kHistoryStorageAddress
// (0x0000F90827F1C53A10CB7A02335B175320002935). Source: https://eips.ethereum.org/EIPS/eip-2935
// §"Specification". Length: 84 bytes (168 hex chars). Logic: when called
// with sender == kSystemAddress it stores parent_hash to ring-buffer slot
// (block_number - 1) % 8191; otherwise serves a parent-block-hash lookup
// keyed by the calldata block number.
constexpr const char* kEip2935Bytecode =
    "3373fffffffffffffffffffffffffffffffffffffffe14604657602036036042575f35600143038111"
    "604257611fff81430311604257611fff9006545f5260205ff35b5f5ffd5b5f35611fff60014303068155"
    "00";

bool hex_decode(const char* hex, silkworm::Bytes& out) {
    size_t len = std::strlen(hex);
    if (len % 2 != 0) return false;
    out.clear();
    out.reserve(len / 2);
    for (size_t i = 0; i < len; i += 2) {
        unsigned x;
        if (std::sscanf(hex + i, "%2x", &x) != 1) return false;
        out.push_back(static_cast<uint8_t>(x));
    }
    return true;
}

}  // anonymous namespace

void seed_eip4788_predeploy(EvmState& state) {
    // The beacon-roots system contract lives at the magic address
    // kBeaconRootsAddress = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02.
    // EIP-4788 deploys it with: nonce = 1, balance = 0, code = the
    // 200-byte runtime above, storage = empty.
    //
    // Idempotent: if the contract is already deployed (correct code_hash),
    // skip — this lets us call seed_eip4788_predeploy() unconditionally on
    // every node startup without re-writing state.
    const evmc::address addr = silkworm::protocol::kBeaconRootsAddress;

    silkworm::Bytes code;
    if (!hex_decode(kEip4788Bytecode, code)) {
        LOG(ERROR) << "evm-workchain: EIP-4788 bytecode literal failed to hex-decode (programmer error)";
        return;
    }

    auto code_hash_kk = ethash::keccak256(code.data(), code.size());
    evmc::bytes32 code_hash{};
    std::memcpy(code_hash.bytes, code_hash_kk.bytes, 32);

    if (auto existing = state.read_account(addr); existing.has_value()) {
        if (existing->code_hash == code_hash) {
            LOG(INFO) << "evm-workchain: EIP-4788 beacon-roots predeploy already present (code_hash match), skipping";
            return;
        }
        LOG(WARNING) << "evm-workchain: EIP-4788 predeploy address has unexpected code_hash; overwriting";
    }

    {
        std::unique_lock lock(state.mutex());
        // Account record (nonce=1, balance=0, code_hash set per EIP).
        silkworm::Account acct;
        acct.nonce = 1;
        acct.balance = 0;
        acct.code_hash = code_hash;
        // Two-step: update_account first (registers the account at code_hash),
        // then update_account_code (stores the actual bytecode and refreshes
        // the embedded EvmAccountData cell so the bytecode survives restart).
        state.state().update_account(addr, std::nullopt, acct);
        state.state().update_account_code(addr, /*incarnation=*/0,
                                          code_hash,
                                          silkworm::ByteView{code.data(), code.size()});
    }

    LOG(WARNING) << "evm-workchain: seeded EIP-4788 beacon-roots predeploy at "
                    "0x000f3df6d732807ef1319fb7b8bb8522d0beac02 (code=97 bytes, nonce=1)";
}

void seed_eip2935_predeploy(EvmState& state) {
    // The history-storage system contract lives at the magic address
    // kHistoryStorageAddress = 0x0000F90827F1C53A10CB7A02335B175320002935.
    // EIP-2935 deploys it with: nonce = 1, balance = 0, code = the
    // 84-byte runtime above, storage = empty.
    //
    // Idempotent (same pattern as seed_eip4788_predeploy).
    const evmc::address addr = silkworm::protocol::kHistoryStorageAddress;

    silkworm::Bytes code;
    if (!hex_decode(kEip2935Bytecode, code)) {
        LOG(ERROR) << "evm-workchain: EIP-2935 bytecode literal failed to hex-decode (programmer error)";
        return;
    }

    auto code_hash_kk = ethash::keccak256(code.data(), code.size());
    evmc::bytes32 code_hash{};
    std::memcpy(code_hash.bytes, code_hash_kk.bytes, 32);

    if (auto existing = state.read_account(addr); existing.has_value()) {
        if (existing->code_hash == code_hash) {
            LOG(INFO) << "evm-workchain: EIP-2935 history-storage predeploy already present (code_hash match), skipping";
            return;
        }
        LOG(WARNING) << "evm-workchain: EIP-2935 predeploy address has unexpected code_hash; overwriting";
    }

    {
        std::unique_lock lock(state.mutex());
        silkworm::Account acct;
        acct.nonce = 1;
        acct.balance = 0;
        acct.code_hash = code_hash;
        state.state().update_account(addr, std::nullopt, acct);
        state.state().update_account_code(addr, /*incarnation=*/0,
                                          code_hash,
                                          silkworm::ByteView{code.data(), code.size()});
    }

    LOG(WARNING) << "evm-workchain: seeded EIP-2935 history-storage predeploy at "
                    "0x0000f90827f1c53a10cb7a02335b175320002935 (code=" << code.size()
                 << " bytes, nonce=1)";
}

void verify_kzg_setup_loaded() {
    // Sanity check: silkworm + evmone bundle the trusted-setup G2_1 point
    // as a constexpr in third-party/evmone/evmone/lib/evmone_precompiles/kzg.cpp.
    // No external trusted_setup file is required and there is no separate
    // loader entry-point — point_evaluation_run() is callable as soon as the
    // process is up.
    //
    // To prove that the precompile is wired into our build (and to surface
    // any future regression early), we run point_evaluation_run on the
    // canonical EIP-4844 spec test vector and assert the success bytes
    // (FIELD_ELEMENTS_PER_BLOB || BLS_MODULUS, 64 bytes total).
    static const uint8_t kInputHex[192] = {
        // versioned_hash (32) — sha256(commitment) with first byte = 0x01
        0x01,0x4e,0xdf,0xed,0x85,0x47,0x66,0x1f,0x6c,0xb4,0x16,0xeb,0xa5,0x30,0x61,0xa2,
        0xf6,0xdc,0xe8,0x72,0xc0,0x49,0x7e,0x6d,0xd4,0x85,0xa8,0x76,0xfe,0x25,0x67,0xf1,
        // z (32) — evaluation point
        0x56,0x4c,0x0a,0x11,0xa0,0xf7,0x04,0xf4,0xfc,0x3e,0x8a,0xcf,0xe0,0xf8,0x24,0x5f,
        0x0a,0xd1,0x34,0x7b,0x37,0x8f,0xbf,0x96,0xe2,0x06,0xda,0x11,0xa5,0xd3,0x63,0x06,
        // y (32) — claimed value at z
        0x6d,0x92,0x8e,0x13,0xfe,0x44,0x3e,0x95,0x7d,0x82,0xe3,0xe7,0x1d,0x48,0xcb,0x65,
        0xd5,0x10,0x28,0xeb,0x44,0x83,0xe7,0x19,0xbf,0x8e,0xfc,0xdf,0x12,0xf7,0xc3,0x21,
        // commitment (48)
        0xa4,0x21,0xe2,0x29,0x56,0x59,0x52,0xcf,0xff,0x4e,0xf3,0x51,0x71,0x00,0xa9,0x7d,
        0xa1,0xd4,0xfe,0x57,0x95,0x6f,0xa5,0x0a,0x44,0x2f,0x92,0xaf,0x03,0xb1,0xbf,0x37,
        0xad,0xac,0xc8,0xad,0x4e,0xd2,0x09,0xb3,0x12,0x87,0xea,0x5b,0xb9,0x4d,0x9d,0x06,
        // proof (48)
        0xa4,0x44,0xd6,0xbb,0x5a,0xad,0xc3,0xce,0xb6,0x15,0xb5,0x0d,0x66,0x06,0xbd,0x54,
        0xbf,0xe5,0x29,0xf5,0x92,0x47,0x98,0x7c,0xd1,0xab,0x84,0x8d,0x19,0xde,0x59,0x9a,
        0x90,0x52,0xf1,0x83,0x5f,0xb0,0xd0,0xd4,0x4c,0xf7,0x01,0x83,0xe1,0x9a,0x68,0xc9,
    };
    auto out = silkworm::precompile::point_evaluation_run(
        silkworm::ByteView{kInputHex, sizeof(kInputHex)});
    if (!out || out->size() != 64) {
        LOG(ERROR) << "evm-workchain: KZG point-evaluation precompile (0x0a) self-test FAILED — "
                      "spec vector did not return 64-byte success blob. "
                      "Cancun activation must NOT proceed.";
        return;
    }
    LOG(WARNING) << "evm-workchain: KZG point-evaluation precompile (0x0a) is ready "
                    "(spec vector verified, no external trusted_setup file needed; "
                    "evmone bundles the G2_1 point as a constexpr)";
}


size_t populate_state_from_shard_accounts(
    EvmState& target,
    vm::AugmentedDictionary& shard_accounts) {
    // Single-executor: the entire EVM world state lives inside the one
    // executor account's StateInit.data (cp.new_data format). Look up
    // kEvmExecutorAddress, decode the state_root ref, and load it into
    // the target's CellEvmState. Returns 1 on success, 0 otherwise.
    auto exec_value = shard_accounts.lookup(
        td::ConstBitPtr{kEvmExecutorAddressBytes}, 256);
    if (exec_value.is_null()) return 0;

    td::Ref<vm::Cell> account_cell;
    if (!block::tlb::t_ShardAccount.extract_account_state(exec_value, account_cell) ||
        account_cell.is_null()) {
        return 0;
    }

    block::gen::Account::Record_account acc_rec;
    if (!tlb::unpack_cell(account_cell, acc_rec)) return 0;

    unsigned long long last_trans_lt;
    td::Ref<vm::CellSlice> balance_cs, state_cs;
    if (!block::gen::t_AccountStorage.unpack_account_storage(
            acc_rec.storage.write(), last_trans_lt, balance_cs, state_cs)) {
        return 0;
    }

    td::Ref<vm::CellSlice> state_init_cs;
    if (!block::gen::t_AccountState.unpack_account_active(state_cs.write(), state_init_cs)) {
        return 0;
    }

    block::gen::StateInit::Record si_rec;
    if (!block::gen::t_StateInit.unpack(state_init_cs.write(), si_rec)) return 0;

    if (si_rec.data.is_null() || !si_rec.data->have(1) ||
        si_rec.data->prefetch_ulong(1) != 1) {
        return 0;
    }
    auto data_slice = si_rec.data;
    data_slice.write().advance(1);
    td::Ref<vm::Cell> cp_new_data_cell;
    if (!data_slice->prefetch_ref_to(cp_new_data_cell)) return 0;

    td::Ref<vm::Cell> state_root;
    evmc::bytes32 native_state_commitment{};
    td::Ref<vm::Cell> rpc_cache_root;  // F.4 will hydrate from this
    td::Ref<vm::Cell> block_hashes_root;
    if (!decode_cp_new_data(cp_new_data_cell, state_root,
                            native_state_commitment, rpc_cache_root,
                            &block_hashes_root,
                            /*block_accumulator_root_out=*/nullptr)) {
        // Audit Q1: the decode failed. Under v6 the only failure modes
        // are a malformed envelope (schema/Maybe-tag/canonical-encoding
        // violation, including a v5 cell rejected at the version gate)
        // or a `native_state_commitment` mismatch against the recomputed
        // commitment over the inner ^state_root. Either way the envelope
        // is unsafe to hydrate from; surface as a hydration-corruption
        // error so downstream consensus / RPC code refuses to operate.
        evmc::bytes32 zero_state_root_hash{};
        mark_evm_hydration_corrupted(
            zero_state_root_hash,
            td::Slice("decode_cp_new_data: cp.new_data envelope rejected "
                      "(malformed schema, non-v6 version, or declared "
                      "native_state_commitment does not match recomputed "
                      "commitment over inner ^state_root)"));
        return 0;
    }
    if (state_root.is_null()) {
        // Audit Q1: a missing inner ^state_root ref is a malformed
        // canonical envelope. Surface as a hydration-corruption error
        // with the same forensic shape as the strict-load case.
        evmc::bytes32 zero_state_root_hash{};
        mark_evm_hydration_corrupted(
            zero_state_root_hash,
            td::Slice("decode_cp_new_data: cp.new_data has no inner "
                      "^state_root ref (envelope advertises no state)"));
        return 0;
    }

    {
        std::unique_lock lock(target.mutex());
        auto* cs = dynamic_cast<CellEvmState*>(&target.state());
        if (!cs) {
            LOG(ERROR) << "evm-workchain: hydration target is not a CellEvmState";
            return 0;
        }
        // Hydration is the canonical "load from a freshly persisted
        // canonical state" path. It runs before any consensus / RPC
        // request can observe `g_evm_state`, so we walk the full
        // account/storage tree under the strict mode. The strict walk
        // funnels every code_root through the H-01 chokepoint
        // (`decode_and_verify_code_root`), so a `keccak(bytecode) !=
        // account.code_hash` mismatch is reported via
        // `last_strict_load_failure_reason()` and surfaced below.
        if (!cs->load_from_cell(state_root,
                                CellStateLoadMode::StrictValidateNative)) {
            // Audit Q1 (tos16 P0 follow-up): the strict cell-state load
            // failed — typically because of a code-root / code-hash
            // mismatch surfaced by `decode_and_verify_code_root`.
            // Surface the descriptive reason captured by the strict
            // walk so the operator / monitoring sees:
            //   * which canonical state_root is corrupt
            //   * which account / code_hash triggered the rejection
            //   * which kind of mismatch the cell-state helper found
            // Mark the global state corrupted (sticky flag) so
            // downstream consensus / RPC code refuses to operate until
            // manual repair / state resync happens. Returning 0 keeps
            // the size_t-returning ABI compatible; the surrounding
            // caller chain (`hydrate_global_state_if_empty`,
            // `init_evm_workchain`) cannot graceful-propagate a Status.
            auto reason = cs->last_strict_load_failure_reason();
            std::string reason_str =
                reason.size() != 0
                    ? std::string(reason.data(), reason.size())
                    : std::string("strict load returned false but no reason "
                                  "was captured (caller bug — please file)");
            evmc::bytes32 state_root_hash{};
            if (state_root.not_null()) {
                auto h = state_root->get_hash().as_array();
                std::memcpy(state_root_hash.bytes, h.data(), 32);
            }
            mark_evm_hydration_corrupted(
                state_root_hash, td::Slice(reason_str));
            return 0;
        }

        // Cross-check the just-loaded state against the declared v6
        // commitment one more time at this layer. The decoder already
        // performed this comparison, but recomputing here defends
        // against a future caller-edit that bypasses the decoder.
        evmc::bytes32 recomputed_commitment =
            compute_native_evm_state_commitment(state_root);
        if (std::memcmp(recomputed_commitment.bytes,
                        native_state_commitment.bytes, 32) != 0) {
            evmc::bytes32 state_root_hash{};
            auto h = state_root->get_hash().as_array();
            std::memcpy(state_root_hash.bytes, h.data(), 32);
            mark_evm_hydration_corrupted(
                state_root_hash,
                td::Slice("hydration: recomputed native_state_commitment "
                          "disagrees with declared cp.new_data commitment "
                          "after strict load (post-decode invariant violation)"));
            return 0;
        }

        if (!cs->load_block_hashes_from_cell(block_hashes_root)) {
            LOG(ERROR) << "evm-workchain: CellEvmState::load_block_hashes_from_cell failed during hydration";
            return 0;
        }
    }
    LOG(WARNING) << "evm-workchain: hydrated world state from executor cell "
                    "(native_state_commitment="
                 << td::Bits256{native_state_commitment.bytes}.to_hex() << ")";
    return 1;
}

td::Ref<vm::Cell> build_evm_zerostate_accounts_cell(
    const std::vector<GenesisAccount>& accounts) {
    // Phase D — parameterised version. Same single-executor wrapper as the
    // zero-arg overload (the wc=1 ShardAccounts dict contains exactly one
    // entry, the executor, whose StateInit.data is a cp.new_data v6 cell
    // referencing a CellEvmState root); the only thing that varies is which
    // accounts are pre-populated inside that state.
    //
    // Layout matches what evm-compute-phase.cpp produces every block so
    // hydration reads exactly the same format whether the chain is at
    // genesis or at block N.

    CellEvmState cell_state;

    // Walk caller-supplied allocs in input order. Each entry produces a
    // sequence of silkworm::State writes that mirror what would happen if
    // the genesis tx synthetically funded / created the account.
    for (const auto& a : accounts) {
        // 1. Account header (balance + nonce). update_account() preserves
        //    storage_root/code_root if the account already exists, so this
        //    is safe to call before update_account_code/update_storage.
        silkworm::Account acct{};
        acct.balance = a.balance;
        acct.nonce = a.nonce;
        cell_state.update_account(a.addr, std::nullopt, acct);

        // 2. Code (only if non-empty — empty bytes ⇒ EOA, code_hash stays
        //    silkworm::kEmptyHash). update_account_code computes the code
        //    hash internally and embeds the bytecode chain via
        //    encode_evm_bytecode().
        if (!a.code.empty()) {
            auto code_hash_be = ethash::keccak256(a.code.data(), a.code.size());
            evmc::bytes32 code_hash{};
            std::memcpy(code_hash.bytes, code_hash_be.bytes, 32);
            cell_state.update_account_code(
                a.addr, /*incarnation=*/0, code_hash,
                silkworm::ByteView{a.code.data(), a.code.size()});
        }

        // 3. Storage slots. Iterate in the caller's std::map order (key-
        //    sorted) so the output is deterministic across runs; values of
        //    zero are no-ops by the silkworm contract.
        static const evmc::bytes32 zero{};
        for (const auto& [slot, value] : a.storage) {
            if (value == zero) continue;
            cell_state.update_storage(a.addr, /*incarnation=*/0, slot, zero, value);
        }
    }
    auto state_root = cell_state.serialize_to_cell();

    // Build cp.new_data v6 cell via the canonical encoder. The native
    // commitment is the cell representation hash of `state_root` (or
    // zero when state_root is null). At genesis there is no RPC cache
    // and no block-hash history yet; the reserved block-accumulator slot
    // is always absent and is handled by the encoder internally.
    evmc::bytes32 native_state_commitment =
        compute_native_evm_state_commitment(state_root);
    auto cp_new_data_cell = encode_cp_new_data_v6(
        state_root, native_state_commitment,
        /*rpc_cache_root=*/{}, /*block_hashes_root=*/{});

    // Wrap as executor ShardAccount and insert as sole entry.
    td::Bits256 exec_addr_bits;
    exec_addr_bits.bits().copy_from(td::ConstBitPtr{kEvmExecutorAddressBytes}, 256);
    auto account_cell = build_evm_shard_account_cell(exec_addr_bits, cp_new_data_cell);

    vm::AugmentedDictionary accounts_dict(256, block::tlb::aug_ShardAccounts);
    vm::CellBuilder vcb;
    vcb.store_ref_bool(account_cell);
    vcb.store_zeroes_bool(256 + 64);  // last_trans_hash + last_trans_lt
    accounts_dict.set_builder(exec_addr_bits.bits(), 256, vcb);

    vm::CellBuilder cb;
    accounts_dict.append_dict_to_bool(cb);
    return cb.finalize();
}

td::Ref<vm::Cell> build_evm_zerostate_accounts_cell() {
#ifndef TOS_DEVNET_ALLOW_TEST_EVM_ACCOUNTS
    LOG(ERROR) << "evm-workchain: zero-arg EVM test zerostate helper is "
                  "disabled in production; use evm-zerostate-from-alloc";
    return {};
#else
    // Devnet-only zero-arg overload: seeds public tutorial accounts with
    // kSeedAmountETos eTOS each. Production genesis must use the
    // parameterised evm-zerostate-from-alloc path instead.
    intx::uint256 amount{kSeedAmountETos};
    for (int i = 0; i < 18; ++i) amount *= intx::uint256{10};

    std::vector<GenesisAccount> accounts;
    accounts.reserve(std::size(kTestAccounts));
    for (const auto& a : kTestAccounts) {
        GenesisAccount g{};
        if (!parse_hex_address(a.address, g.addr)) continue;
        g.balance = amount;
        g.nonce = 0;
        accounts.push_back(std::move(g));
    }
    return build_evm_zerostate_accounts_cell(accounts);
#endif
}

size_t hydrate_global_state_if_empty(vm::AugmentedDictionary& shard_accounts) {
    if (!g_evm_state) return 0;
    // One-shot per process. Devnet-only bootstrap may prepopulate the
    // singleton before canonical shard state hydration, but the process still
    // needs to hydrate from wc=1 ShardAccounts exactly once.
    if (!g_evm_state->needs_initial_hydration()) return 0;
    if (shard_accounts.is_empty()) return 0;

    auto count = populate_state_from_shard_accounts(*g_evm_state, shard_accounts);

    // Audit Q1 / tos17 M-02 fail-closed: if hydration corrupted the state
    // (decode rejection, code_hash mismatch, post-decode invariant
    // violation, etc.), DO NOT mark initial hydration as done. Leaving
    // the flag unset means downstream readers see
    // `needs_initial_hydration() == true` and the sticky
    // `evm_hydration_corrupted()` flag is set — every consensus / RPC
    // entry point that consults the flag will refuse to operate until
    // an operator restart from a known-good snapshot.
    if (evm_hydration_corrupted()) {
        LOG(ERROR) << "evm-workchain: canonical hydration corrupted: "
                   << evm_hydration_failure_reason();
        return 0;  // intentionally do NOT mark done — readers fail closed
    }

    if (count == 0) {
        // No executor account present yet (the shard state we were given
        // does not yet carry an EVM account). Leave the hydration flag
        // unset so a later, more complete shard state can still hydrate.
        return 0;
    }

    g_evm_state->mark_initial_hydration_done();
    return count;
}

void init_evm_workchain(const std::string& db_root) {
    // db_root historically pointed at the legacy evm-state.boc sidecar
    // location (removed in Phase B — canonical state lives in wc=1
    // ShardAccounts now). It now serves Phase F.3/F.4: open the
    // side-channel RPC cache DB at db_root + "/evm-rpc-cache" so
    // receipts survive restart without touching consensus.

    // Production validators must not derive consensus-critical chain_id from
    // process-local environment. Devnet/Hive builds may opt in explicitly.
#ifdef TOS_DEVNET_ALLOW_EVM_CHAIN_ID_ENV
    if (const char* env = std::getenv("TOS_EVM_CHAIN_ID"); env && *env) {
        char* endp = nullptr;
        // Accept both decimal ("5525331") and hex ("0x544f53") forms.
        unsigned long long parsed = std::strtoull(env, &endp, 0);
        if (endp == env || *endp != '\0' || parsed == 0) {
            LOG(ERROR) << "evm-workchain: ignoring TOS_EVM_CHAIN_ID='" << env
                       << "' (failed to parse as positive integer)";
        } else {
            set_evm_chain_id(static_cast<uint64_t>(parsed));
            LOG(WARNING) << "evm-workchain: TOS_EVM_CHAIN_ID override → 0x"
                         << std::hex << current_evm_chain_id() << std::dec
                         << " (default would have been 0x" << std::hex
                         << kEvmChainId << std::dec << ")";
        }
    }
#else
    if (const char* env = std::getenv("TOS_EVM_CHAIN_ID"); env && *env) {
        LOG(WARNING) << "evm-workchain: ignoring TOS_EVM_CHAIN_ID in this build; "
                     << "chain_id is consensus-critical and must come from "
                     << "the chain configuration";
    }
#endif

    LOG(WARNING) << "evm-workchain: initialising (default_workchain_id=" << kWorkchainId
                 << ", chain_id="
                 << current_evm_chain_id() << ")";

    // Cell-native state. The dictionary starts empty here; the canonical
    // wc=1 ShardAccounts (loaded by the collator/validate-query from CellDb)
    // is what populates this state via populate_state_from_shard_accounts()
    // on the first wc=1 block load. The previous evm-state.boc sidecar load
    // path was removed in Phase B — there is no second store anymore.
    auto cell_state = std::make_unique<CellEvmState>();
    g_evm_state = std::make_unique<EvmState>(std::move(cell_state));

#ifdef TOS_DEVNET_ALLOW_TEST_EVM_ACCOUNTS
    // Devnet-only convenience accounts. Production builds do not seed public
    // test keys into the runtime singleton or genesis.
    seed_test_accounts(*g_evm_state);
#endif

    // Cancun pre-fork prep (Category E in known-divergences). Both calls are
    // safe at the current Shanghai-revision config — they only matter once
    // cancun_time = 0 is flipped:
    //   * KZG self-test logs readiness of precompile 0x0a (no init action,
    //     just a sanity check that the bundled G2_1 setup is linked).
    //   * Beacon-roots predeploy is idempotent — once it's in CellEvmState
    //     it round-trips through cp.new_data → restart with the right
    //     code_hash, and we skip on subsequent calls.
    verify_kzg_setup_loaded();
    seed_eip4788_predeploy(*g_evm_state);
    seed_eip2935_predeploy(*g_evm_state);  // EIP-2935 (Pectra)

    // Phase F.3/F.4: open the per-validator side-channel RPC cache DB.
    // Skipped on the test harness path (no db_root provided).
    if (!db_root.empty()) {
        auto cache_path = db_root + "/evm-rpc-cache";
        auto db_r = EvmRpcCacheDb::open(cache_path);
        if (db_r.is_error()) {
            LOG(ERROR) << "evm-workchain: failed to open rpc cache db at "
                       << cache_path << ": " << db_r.error().message();
        } else {
            set_evm_rpc_cache_db(db_r.move_as_ok());
            // Hydrate g_evm_state.receipts_ from the cache so RPC
            // queries for pre-restart txs return data immediately.
            size_t hydrated = 0;
            size_t decode_fails = 0;
            auto walk_status = evm_rpc_cache_db()->for_each_receipt(
                [&hydrated, &decode_fails](const td::Bits256& tx_hash,
                            td::Ref<vm::Cell> cell) -> td::Status {
                    StoredReceipt r;
                    EvmCacheRecordStamp out_stamp;  // hydration trusts canonical state; stamp unused
                    if (!decode_persisted_receipt(cell, r, out_stamp)) {
                        ++decode_fails;
                        return td::Status::OK();
                    }
                    (void)out_stamp;
                    evmc::bytes32 tx_hash_be{};
                    std::memcpy(tx_hash_be.bytes, tx_hash.data(), 32);
                    g_evm_state->store_receipt(tx_hash_be, std::move(r));
                    ++hydrated;
                    return td::Status::OK();
                });
            if (walk_status.is_error()) {
                LOG(ERROR) << "evm-workchain: rpc cache walk failed: "
                           << walk_status.message();
            } else {
                LOG(WARNING) << "evm-workchain: hydrated " << hydrated
                             << " receipts from rpc cache db"
                             << (decode_fails > 0 ? " (skipped " + std::to_string(decode_fails) + " corrupt entries)" : "");
            }

            // Phase F.6: hydrate transactions, blocks (both indexes) and
            // per-block log vectors. Each walk is independent and uses the
            // same EvmState mutators that compute-phase calls; they are all
            // idempotent for replays.
            size_t txs_hydrated = 0, tx_decode_fails = 0;
            auto tx_walk = evm_rpc_cache_db()->for_each_transaction(
                [&txs_hydrated, &tx_decode_fails](const td::Bits256& tx_hash,
                            td::Ref<vm::Cell> cell) -> td::Status {
                    StoredTransaction t;
                    EvmCacheRecordStamp out_stamp;  // hydration trusts canonical state; stamp unused
                    if (!decode_persisted_transaction(cell, t, out_stamp)) {
                        ++tx_decode_fails;
                        return td::Status::OK();
                    }
                    (void)out_stamp;
                    evmc::bytes32 tx_hash_be{};
                    std::memcpy(tx_hash_be.bytes, tx_hash.data(), 32);
                    g_evm_state->store_transaction(tx_hash_be, std::move(t));
                    ++txs_hydrated;
                    return td::Status::OK();
                });
            if (tx_walk.is_error()) {
                LOG(ERROR) << "evm-workchain: rpc cache tx walk failed: "
                           << tx_walk.message();
            } else {
                LOG(WARNING) << "evm-workchain: hydrated " << txs_hydrated
                             << " transactions from rpc cache db"
                             << (tx_decode_fails > 0 ? " (skipped " + std::to_string(tx_decode_fails) + " corrupt entries)" : "");
            }

            size_t blocks_hydrated = 0, block_decode_fails = 0,
                   blocks_orphaned = 0;
            // Walk by-number first so chain-order iteration populates
            // hash_to_block_ alongside blocks_; the by-hash walk is then a
            // safety-net (no-op if both indexes were written together).
            //
            // Round 88 MEDIUM fix: during hydration, gate every cached
            // block against the canonical chain via
            // CellEvmState::canonical_hash(block_num).  Pre-fix the
            // walker blindly stored any persisted block, so a node
            // that died after a same-height rewrite RAM-mutated state
            // but before `cache->put_block_by_number` finished left
            // the OLD block-by-number entry in the cache DB.  Restart
            // hydration would resurrect that orphaned block, and
            // `eth_getBlockByNumber(N)` could serve the old hash even
            // though canonical state had moved on.  When canonical
            // state knows a hash for that height and it disagrees
            // with the cached entry, drop the cached block.
            auto block_walk = evm_rpc_cache_db()->for_each_block_by_number(
                [&blocks_hydrated, &block_decode_fails, &blocks_orphaned](
                    uint64_t block_number, td::Ref<vm::Cell> cell) -> td::Status {
                    StoredBlock b;
                    EvmCacheRecordStamp out_stamp;  // hydration trusts canonical state; stamp unused
                    if (!decode_persisted_block(cell, b, out_stamp)) {
                        ++block_decode_fails;
                        return td::Status::OK();
                    }
                    (void)out_stamp;
                    auto canonical = g_evm_state->state().canonical_hash(
                        static_cast<silkworm::BlockNum>(block_number));
                    if (canonical.has_value() && *canonical != b.hash) {
                        ++blocks_orphaned;
                        return td::Status::OK();
                    }
                    g_evm_state->store_block(b);
                    ++blocks_hydrated;
                    return td::Status::OK();
                });
            if (block_walk.is_error()) {
                LOG(ERROR) << "evm-workchain: rpc cache block walk failed: "
                           << block_walk.message();
            } else {
                std::string suffix;
                if (block_decode_fails > 0) {
                    suffix += " (skipped " + std::to_string(block_decode_fails) + " corrupt entries)";
                }
                if (blocks_orphaned > 0) {
                    suffix += " (skipped " + std::to_string(blocks_orphaned) + " same-height orphans)";
                }
                LOG(WARNING) << "evm-workchain: hydrated " << blocks_hydrated
                             << " blocks from rpc cache db" << suffix;
            }

            // Logs walk: each entry is the full IndexedLog vector for a
            // block. The state's store_logs() appends per-tx entries with a
            // log_index derived from the existing vector size, which would
            // mis-number if we replayed per-tx; instead we write directly into
            // the block_logs_ slot via repeated store_logs grouped by tx_hash.
            size_t log_blocks_hydrated = 0;
            size_t log_decode_fails = 0;
            auto logs_walk = evm_rpc_cache_db()->for_each_block_logs(
                [&log_blocks_hydrated, &log_decode_fails](
                    uint64_t block_number, td::Ref<vm::Cell> cell) -> td::Status {
                    std::vector<IndexedLog> logs;
                    EvmCacheRecordStamp out_stamp;  // hydration trusts canonical state; stamp unused
                    if (!decode_persisted_logs_for_block(cell, logs, out_stamp)) {
                        ++log_decode_fails;
                        return td::Status::OK();
                    }
                    (void)out_stamp;
                    // Re-group by tx_hash preserving order so store_logs
                    // recreates the original log_index sequence. Each
                    // store_logs call appends `logs.size()` entries with
                    // log_index continuing from the current vector size.
                    std::vector<silkworm::Log> bucket;
                    evmc::bytes32 cur_tx{};
                    uint32_t cur_tx_index = 0;
                    bool first = true;
                    auto flush = [&]() {
                        if (bucket.empty()) return;
                        g_evm_state->store_logs(block_number, cur_tx, bucket, cur_tx_index);
                        bucket.clear();
                    };
                    for (const auto& il : logs) {
                        if (first || il.tx_hash != cur_tx) {
                            flush();
                            cur_tx = il.tx_hash;
                            cur_tx_index = il.tx_index;
                            first = false;
                        }
                        bucket.push_back(il.log);
                    }
                    flush();
                    ++log_blocks_hydrated;
                    return td::Status::OK();
                });
            if (logs_walk.is_error()) {
                LOG(ERROR) << "evm-workchain: rpc cache logs walk failed: "
                           << logs_walk.message();
            } else {
                LOG(WARNING) << "evm-workchain: hydrated logs for "
                             << log_blocks_hydrated << " blocks from rpc cache db"
                             << (log_decode_fails > 0 ? " (skipped " + std::to_string(log_decode_fails) + " corrupt entries)" : "");
            }

            hydrate_evm_rpc_incomplete_indexes_from_cache();
        }
    }

    register_evm_workchain_engine(
        block::default_workchain_execution_registry());

    LOG(WARNING) << "evm-workchain: handler registered";
}

}  // namespace evm_workchain
