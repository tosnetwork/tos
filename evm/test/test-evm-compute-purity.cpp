/*
    EVM Workchain — compute-phase purity (P1 audit closure) tests.

    Pins the contract that `run_evm_compute_phase_snapshot` is a pure
    function of (`account_data`, `in_msg_body`, `gas_limit`, block metadata):
    repeated calls with byte-identical inputs MUST yield byte-identical
    `cp.new_data` cell hashes, regardless of the in-process g_evm_state's
    history.

    Tests:
      1. same_block_validated_twice_is_idempotent
      2. collator_validator_agree_on_state_root
      3. fork_order_independence
      4. restart_validator_matches_collator

    Build target: test-evm-compute-purity (see evm/test/CMakeLists.txt)
*/

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>

#include "block/transaction.h"
#include "block/evm-workchain-dispatch.h"

#include "evm/core/cell-codec.h"
#include "evm/core/cell-state.h"
#include "evm/core/compute-phase.h"
#include "evm/core/init.h"
#include "evm/core/post-accept.h"
#include "evm/core/state.h"
#include "evm/core/transaction.h"
#include "evm/core/workchain.h"

#include "vm/cells/CellBuilder.h"
#include "vm/cellslice.h"

#include <silkworm/core/types/transaction.hpp>
#include <silkworm/core/rlp/encode.hpp>
#include <silkworm/core/types/account.hpp>

#include <ethash/keccak.hpp>
#include <secp256k1.h>
#include <secp256k1_recovery.h>

// ---------------------------------------------------------------------------
// Tracked-printf harness (mirrors uno/test/test-mine-uno-cpp.cpp)
// ---------------------------------------------------------------------------

static std::atomic<int> g_failures{0};
static std::atomic<int> g_passes{0};
static std::atomic<int> g_skips{0};

static int tracked_printf(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    va_list copy;
    va_copy(copy, args);
    int needed = std::vsnprintf(nullptr, 0, fmt, copy);
    va_end(copy);
    std::string rendered;
    if (needed >= 0) {
        rendered.resize(static_cast<size_t>(needed) + 1);
        va_copy(copy, args);
        std::vsnprintf(rendered.data(), rendered.size(), fmt, copy);
        va_end(copy);
        rendered.resize(static_cast<size_t>(needed));
    }
    int written = std::vprintf(fmt, args);
    va_end(args);
    if (!rendered.empty()) {
        if (rendered.find("FAILED") != std::string::npos) g_failures.fetch_add(1);
        if (rendered.find("PASSED") != std::string::npos) g_passes.fetch_add(1);
        if (rendered.find("SKIP")   != std::string::npos) g_skips.fetch_add(1);
    }
    return written;
}
#define tprintf tracked_printf

namespace ew = evm_workchain;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Build a `cp.new_data` v2 cell wrapping the supplied state_root cell. Same
// layout that `run_evm_compute_phase_snapshot` itself emits (and that the
// genesis builder produces): magic + has_root + ^state_root + 256-bit
// eth_state_root (zero here) + has_cache=0.
static td::Ref<vm::Cell> wrap_state_root_as_account_data(td::Ref<vm::Cell> state_root) {
    vm::CellBuilder cb;
    cb.store_long(static_cast<long long>(ew::kEvmAccountMagic), ew::kEvmMagicBits);
    if (state_root.not_null()) {
        cb.store_long(1, 1);
        cb.store_ref(state_root);
    } else {
        cb.store_long(0, 1);
    }
    cb.store_zeroes(256);
    cb.store_long(0, 1);
    return cb.finalize();
}

// Build an account_data cell with `sender` seeded with `balance` and `nonce`.
static td::Ref<vm::Cell> make_account_data_with_funded_sender(
    const evmc::address& sender,
    const intx::uint256& balance,
    uint64_t nonce) {
    ew::CellEvmState cs;
    silkworm::Account acct{};
    acct.balance = balance;
    acct.nonce = nonce;
    cs.update_account(sender, std::nullopt, acct);
    return wrap_state_root_as_account_data(cs.serialize_to_cell());
}

// secp256k1 single context, kept alive for the test binary's lifetime.
static secp256k1_context* sec_ctx() {
    static secp256k1_context* ctx =
        secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    return ctx;
}

struct SignedRawTx {
    silkworm::Bytes raw_rlp;
    evmc::address sender;
    evmc::bytes32 hash;
};

// Sign a simple legacy ETH transfer with the given private key seed,
// nonce, recipient, and value. Mirrors the helper in test-executor.cpp.
static std::optional<SignedRawTx> make_signed_transfer(
    uint32_t key_seed,
    uint64_t nonce,
    const evmc::address& recipient,
    const intx::uint256& value = intx::uint256{1'000'000},
    uint64_t gas_limit = 50'000) {

    auto* ctx = sec_ctx();
    uint8_t privkey[32] = {};
    privkey[28] = static_cast<uint8_t>((key_seed >> 24) & 0xff);
    privkey[29] = static_cast<uint8_t>((key_seed >> 16) & 0xff);
    privkey[30] = static_cast<uint8_t>((key_seed >> 8) & 0xff);
    privkey[31] = static_cast<uint8_t>(key_seed & 0xff);
    if (key_seed == 0) privkey[31] = 1;

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privkey)) return std::nullopt;
    uint8_t pub_serialized[65];
    size_t pub_len = 65;
    secp256k1_ec_pubkey_serialize(ctx, pub_serialized, &pub_len, &pubkey,
                                  SECP256K1_EC_UNCOMPRESSED);
    auto pub_hash = ethash::keccak256(pub_serialized + 1, 64);
    evmc::address sender{};
    std::memcpy(sender.bytes, pub_hash.bytes + 12, 20);

    silkworm::Transaction txn;
    txn.type = silkworm::TransactionType::kLegacy;
    txn.chain_id = ew::kEvmChainId;
    txn.nonce = nonce;
    txn.max_fee_per_gas = 1'000'000'000;
    txn.max_priority_fee_per_gas = 1'000'000'000;
    txn.gas_limit = gas_limit;
    txn.to = recipient;
    txn.value = value;

    silkworm::Bytes signing_data;
    txn.encode_for_signing(signing_data);
    auto msg_hash = ethash::keccak256(signing_data.data(), signing_data.size());

    secp256k1_ecdsa_recoverable_signature sig;
    if (!secp256k1_ecdsa_sign_recoverable(ctx, &sig, msg_hash.bytes, privkey,
                                           nullptr, nullptr)) {
        return std::nullopt;
    }
    uint8_t sig_bytes[64];
    int recovery_id = 0;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig_bytes,
                                                              &recovery_id, &sig);
    txn.r = intx::be::unsafe::load<intx::uint256>(sig_bytes);
    txn.s = intx::be::unsafe::load<intx::uint256>(sig_bytes + 32);
    txn.odd_y_parity = (recovery_id == 1);
    txn.set_v(intx::uint256{ew::kEvmChainId * 2 + 35 + recovery_id});

    silkworm::Bytes raw_rlp;
    silkworm::rlp::encode(raw_rlp, txn);
    auto tx_hash = txn.hash();
    return SignedRawTx{std::move(raw_rlp), sender, tx_hash};
}

// Wrap raw RLP bytes into a body cell that `extract_evm_payload` accepts.
static td::Ref<vm::Cell> make_body_cell_from_rlp(const silkworm::Bytes& raw) {
    return ew::encode_evm_bytecode(
        td::Slice{reinterpret_cast<const char*>(raw.data()), raw.size()});
}

// Run snapshot compute once. Returns the produced cp.new_data cell hash.
struct ComputeOutcome {
    bool ok{false};
    bool success{false};
    int skip_reason{0};
    td::Ref<vm::Cell> new_data;
};
static ComputeOutcome run_once(td::Ref<vm::Cell> account_data,
                                const silkworm::Bytes& raw_rlp,
                                uint64_t block_seqno = 1,
                                uint64_t timestamp = 1700000000,
                                uint64_t gas_limit = 1'000'000) {
    auto body_cell = make_body_cell_from_rlp(raw_rlp);
    if (body_cell.is_null()) return {};
    auto body_cs = vm::load_cell_slice(body_cell);
    block::ComputePhase cp{};
    uint8_t rand_seed[32] = {};
    uint8_t parent_block_hash[32] = {};
    bool ok = ew::run_evm_compute_phase_snapshot(
        cp, std::move(account_data), body_cs, gas_limit,
        block_seqno, timestamp, rand_seed, parent_block_hash);
    return ComputeOutcome{ok, cp.success, cp.skip_reason, cp.new_data};
}

// Compare two non-null cells by their canonical hash.
static bool cells_hash_equal(const td::Ref<vm::Cell>& a, const td::Ref<vm::Cell>& b) {
    if (a.is_null() || b.is_null()) return false;
    return a->get_hash() == b->get_hash();
}

// ---------------------------------------------------------------------------
// Test 1 — same_block_validated_twice_is_idempotent
// ---------------------------------------------------------------------------
//
// Calling the snapshot variant twice on the same `account_data` MUST
// produce bitwise-identical `cp.new_data` cells and `cp.success == true`
// both times. Under the legacy global-state path the second call would
// see a post-state nonce already incremented and revert with
// "nonce too low" (silkworm error), recording a failed receipt that
// overwrote the first.

static void test_same_block_validated_twice_is_idempotent() {
    tprintf("[TEST] same_block_validated_twice_is_idempotent\n");

    evmc::address recipient{};
    recipient.bytes[19] = 0x99;

    auto signed_tx = make_signed_transfer(/*key_seed=*/0xC0FFEE, /*nonce=*/0, recipient);
    if (!signed_tx) {
        tprintf("  FAILED: could not sign tx\n");
        return;
    }
    intx::uint256 balance{1};
    for (int i = 0; i < 18; ++i) balance *= intx::uint256{10};  // 1 ETH
    auto account_data =
        make_account_data_with_funded_sender(signed_tx->sender, balance, /*nonce=*/0);

    auto first = run_once(account_data, signed_tx->raw_rlp);
    auto second = run_once(account_data, signed_tx->raw_rlp);

    if (!first.ok || !second.ok) {
        tprintf("  FAILED: handler returned false (first.ok=%d second.ok=%d)\n",
                first.ok, second.ok);
        return;
    }
    if (!first.success) {
        tprintf("  FAILED: first call did not succeed (skip_reason=%d)\n",
                first.skip_reason);
        return;
    }
    if (!second.success) {
        tprintf("  FAILED: second call did not succeed (skip_reason=%d) — "
                "the legacy global-state bug would land here\n",
                second.skip_reason);
        return;
    }
    if (!cells_hash_equal(first.new_data, second.new_data)) {
        tprintf("  FAILED: cp.new_data hashes diverge across two pure calls\n");
        return;
    }
    tprintf("  PASSED (cp.new_data hashes match across two calls on the same pre-state)\n");
}

// ---------------------------------------------------------------------------
// Test 2 — collator_validator_agree_on_state_root
// ---------------------------------------------------------------------------
//
// Two notional roles (collator / validator) execute the same tx against
// the same `account_data`. With pure compute their cp.new_data hashes
// MUST match. (Today nothing would distinguish them in a test harness;
// we still pin the invariant explicitly to catch a future regression
// where compute starts reading some hidden process-local state.)

static void test_collator_validator_agree_on_state_root() {
    tprintf("[TEST] collator_validator_agree_on_state_root\n");

    evmc::address recipient{};
    recipient.bytes[19] = 0x42;

    auto tx = make_signed_transfer(/*key_seed=*/0xBEEF, /*nonce=*/0, recipient);
    if (!tx) {
        tprintf("  FAILED: signing failed\n");
        return;
    }
    intx::uint256 balance{1};
    for (int i = 0; i < 18; ++i) balance *= intx::uint256{10};
    auto account_data = make_account_data_with_funded_sender(
        tx->sender, balance, /*nonce=*/0);

    // Two independent calls, mimicking two roles in two notional
    // EvmState environments. Snapshot compute carries no environment
    // dependency beyond `account_data` + msg + block metadata.
    auto collator_out = run_once(account_data, tx->raw_rlp);
    auto validator_out = run_once(account_data, tx->raw_rlp);

    if (!collator_out.success || !validator_out.success) {
        tprintf("  FAILED: collator success=%d validator success=%d\n",
                collator_out.success, validator_out.success);
        return;
    }
    if (!cells_hash_equal(collator_out.new_data, validator_out.new_data)) {
        tprintf("  FAILED: collator vs validator cp.new_data hashes differ\n");
        return;
    }
    tprintf("  PASSED (collator and validator produce equal cp.new_data hashes)\n");
}

// ---------------------------------------------------------------------------
// Test 3 — fork_order_independence
// ---------------------------------------------------------------------------
//
// Two competing candidates X and Y at the same height share the same
// pre-state P. Each candidate is fully a function of (P, msg_X) and
// (P, msg_Y) — the order in which a node sees them must NOT change
// either's cp.new_data. Apply X→Y→X and Y→X→Y and compare.

static void test_fork_order_independence() {
    tprintf("[TEST] fork_order_independence\n");

    evmc::address recipient{};
    recipient.bytes[19] = 0x77;

    auto txX = make_signed_transfer(/*key_seed=*/0xAAAA, /*nonce=*/0, recipient,
                                     /*value=*/intx::uint256{1});
    auto txY = make_signed_transfer(/*key_seed=*/0xBBBB, /*nonce=*/0, recipient,
                                     /*value=*/intx::uint256{2});
    if (!txX || !txY) {
        tprintf("  FAILED: signing failed\n");
        return;
    }
    intx::uint256 balance{1};
    for (int i = 0; i < 18; ++i) balance *= intx::uint256{10};

    // Each candidate has its own funded sender — pre-state P contains
    // both EOAs so either tx can run independently against the same P.
    ew::CellEvmState cs;
    silkworm::Account ax{};
    ax.balance = balance;
    ax.nonce = 0;
    cs.update_account(txX->sender, std::nullopt, ax);
    silkworm::Account ay{};
    ay.balance = balance;
    ay.nonce = 0;
    cs.update_account(txY->sender, std::nullopt, ay);
    auto account_data_P = wrap_state_root_as_account_data(cs.serialize_to_cell());

    // Apply X→Y→X
    auto x1 = run_once(account_data_P, txX->raw_rlp);
    auto y1 = run_once(account_data_P, txY->raw_rlp);
    auto x2 = run_once(account_data_P, txX->raw_rlp);
    // Apply Y→X→Y
    auto y2 = run_once(account_data_P, txY->raw_rlp);
    auto x3 = run_once(account_data_P, txX->raw_rlp);
    auto y3 = run_once(account_data_P, txY->raw_rlp);

    if (!x1.success || !y1.success || !x2.success ||
        !y2.success || !x3.success || !y3.success) {
        tprintf("  FAILED: one of the six runs did not succeed "
                "(x1=%d y1=%d x2=%d y2=%d x3=%d y3=%d)\n",
                x1.success, y1.success, x2.success,
                y2.success, x3.success, y3.success);
        return;
    }
    if (!cells_hash_equal(x1.new_data, x2.new_data) ||
        !cells_hash_equal(x1.new_data, x3.new_data)) {
        tprintf("  FAILED: candidate X cp.new_data depends on apply order\n");
        return;
    }
    if (!cells_hash_equal(y1.new_data, y2.new_data) ||
        !cells_hash_equal(y1.new_data, y3.new_data)) {
        tprintf("  FAILED: candidate Y cp.new_data depends on apply order\n");
        return;
    }
    tprintf("  PASSED (X and Y are each invariant under apply order)\n");
}

// ---------------------------------------------------------------------------
// Test 4 — restart_validator_matches_collator
// ---------------------------------------------------------------------------
//
// Compute against a hot pre-state P (collator) → record cp.new_data.
// Re-run the same tx against the same P, but as if from a freshly
// started process — this is just another snapshot call, by design (the
// snapshot path does not consult any process-global mutable state). The
// hashes MUST match.

static void test_restart_validator_matches_collator() {
    tprintf("[TEST] restart_validator_matches_collator\n");

    evmc::address recipient{};
    recipient.bytes[19] = 0xAB;

    auto tx = make_signed_transfer(/*key_seed=*/0xDEAD, /*nonce=*/0, recipient);
    if (!tx) {
        tprintf("  FAILED: signing failed\n");
        return;
    }
    intx::uint256 balance{1};
    for (int i = 0; i < 18; ++i) balance *= intx::uint256{10};
    auto account_data = make_account_data_with_funded_sender(
        tx->sender, balance, /*nonce=*/0);

    auto hot = run_once(account_data, tx->raw_rlp);

    // Simulate "restart": a brand-new ComputePhase instance, no shared
    // state of any kind — just the same byte-equal `account_data` cell
    // and message body.
    auto cold = run_once(account_data, tx->raw_rlp);

    if (!hot.success || !cold.success) {
        tprintf("  FAILED: hot.success=%d cold.success=%d\n",
                hot.success, cold.success);
        return;
    }
    if (!cells_hash_equal(hot.new_data, cold.new_data)) {
        tprintf("  FAILED: hot vs cold cp.new_data hashes differ — "
                "restart-validator divergence reproduced\n");
        return;
    }
    tprintf("  PASSED (cp.new_data is byte-equal across hot / cold runs)\n");
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    tprintf("EVM Workchain — compute-phase purity (P1 audit closure) tests\n");
    tprintf("==============================================================\n\n");

    // Bring up g_evm_state + g_trie_calc + the dispatch handler. The
    // snapshot path calls into global_trie_calculator() and the
    // post-accept apply layer reads global_evm_state(); both null-check
    // would crash without a prior init.
    ew::init_evm_workchain();

    test_same_block_validated_twice_is_idempotent();
    test_collator_validator_agree_on_state_root();
    test_fork_order_independence();
    test_restart_validator_matches_collator();

    tprintf("\nTotal: passed=%d, failures=%d, skips=%d\n",
            g_passes.load(), g_failures.load(), g_skips.load());
    return g_failures.load() == 0 ? 0 : 1;
}
