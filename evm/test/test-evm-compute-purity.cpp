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
      5. post_accept_missing_side_effect_keeps_prefix_indices

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
#include "evm/core/external-message.h"
#include "evm/core/init.h"
#include "evm/core/incremental-trie.h"
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

static evmc::bytes32 compute_eth_state_root_from_cell(td::Ref<vm::Cell> state_root) {
    auto cell_state = std::make_unique<ew::CellEvmState>();
    if (state_root.not_null()) {
        CHECK(cell_state->load_from_cell(state_root));
    }
    ew::EvmState state(std::move(cell_state));
    std::unique_lock lock(state.mutex());
    ew::IncrementalTrieCalculator calc;
    return calc.compute_state_root(state, nullptr, nullptr);
}

// Build a `cp.new_data` v2 cell wrapping the supplied state_root cell. Same
// layout that `run_evm_compute_phase_snapshot` itself emits (and that the
// genesis builder produces): magic + has_root + ^state_root + 256-bit
// verified eth_state_root + has_cache=0.
static td::Ref<vm::Cell> wrap_state_root_as_account_data(td::Ref<vm::Cell> state_root) {
    auto eth_state_root = compute_eth_state_root_from_cell(state_root);
    vm::CellBuilder cb;
    cb.store_long(static_cast<long long>(ew::kEvmAccountMagic), ew::kEvmMagicBits);
    if (state_root.not_null()) {
        cb.store_long(1, 1);
        cb.store_ref(state_root);
    } else {
        cb.store_long(0, 1);
    }
    cb.store_bytes(reinterpret_cast<const char*>(eth_state_root.bytes), 32);
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
// Test 5 — post_accept_missing_side_effect_keeps_prefix_indices
// ---------------------------------------------------------------------------
//
// If the deferred side-effect cache misses in the middle of an accepted
// block, post-accept must not compress later records onto the missing
// tx_index. Publish only the complete prefix so tx_index and
// cumulativeGasUsed remain exact for every emitted record.

static ew::EvmBlockSideEffects make_test_side_effect(
    const SignedRawTx& tx,
    const evmc::address& recipient,
    uint64_t gas_used,
    uint8_t root_marker) {
    ew::EvmBlockSideEffects fx;
    fx.tx_hash = tx.hash;
    fx.receipt.success = true;
    fx.receipt.gas_used = gas_used;
    fx.receipt.cumulative_gas_used = gas_used;
    fx.receipt.from = tx.sender;
    fx.receipt.to = recipient;
    fx.transaction.from = tx.sender;
    fx.transaction.to = recipient;
    fx.transaction.value = intx::uint256{1'000'000};
    fx.transaction.nonce = 0;
    fx.transaction.gas_limit = 50'000;
    fx.transaction.gas_price = intx::uint256{1'000'000'000};
    fx.transaction.raw_rlp = tx.raw_rlp;
    fx.has_block = true;
    fx.block.gas_used = gas_used;
    fx.block.gas_limit = 30'000'000;
    fx.block.base_fee_per_gas = intx::uint256{1'000'000'000};
    fx.block.transaction_hashes.push_back(tx.hash);
    fx.block.state_root.bytes[31] = root_marker;
    return fx;
}

static void test_post_accept_missing_side_effect_keeps_prefix_indices() {
    tprintf("[TEST] post_accept_missing_side_effect_keeps_prefix_indices\n");

    evmc::address recipient{};
    recipient.bytes[19] = 0x73;
    auto tx0 = make_signed_transfer(/*key_seed=*/0xF40001, /*nonce=*/0, recipient);
    auto tx1 = make_signed_transfer(/*key_seed=*/0xF40002, /*nonce=*/0, recipient);
    auto tx2 = make_signed_transfer(/*key_seed=*/0xF40003, /*nonce=*/0, recipient);
    if (!tx0 || !tx1 || !tx2) {
        tprintf("  FAILED: could not sign test txs\n");
        return;
    }

    std::vector<td::Ref<vm::Cell>> msgs;
    msgs.push_back(ew::build_evm_external_message(tx0->raw_rlp.data(),
                                                  tx0->raw_rlp.size(),
                                                  tx0->sender));
    msgs.push_back(ew::build_evm_external_message(tx1->raw_rlp.data(),
                                                  tx1->raw_rlp.size(),
                                                  tx1->sender));
    msgs.push_back(ew::build_evm_external_message(tx2->raw_rlp.data(),
                                                  tx2->raw_rlp.size(),
                                                  tx2->sender));
    if (msgs[0].is_null() || msgs[1].is_null() || msgs[2].is_null()) {
        tprintf("  FAILED: could not build external messages\n");
        return;
    }

    const uint64_t block_seqno = 424242;
    const uint64_t timestamp = 1800000000;
    uint8_t rand_seed[32] = {};
    uint8_t parent_hash[32] = {};
    rand_seed[31] = 0x5a;
    parent_hash[31] = 0xa5;

    const size_t before_stash_count = ew::stashed_side_effects_count();
    ew::stash_side_effects(block_seqno, timestamp, rand_seed, parent_hash,
                           tx0->hash,
                           make_test_side_effect(*tx0, recipient, 21'000, 0x10));
    // Intentionally do not stash tx1: this simulates eviction / restart /
    // compute-side omission in the middle of the accepted block.
    ew::stash_side_effects(block_seqno, timestamp, rand_seed, parent_hash,
                           tx2->hash,
                           make_test_side_effect(*tx2, recipient, 23'000, 0x30));

    size_t applied = ew::apply_stashed_side_effects_for_messages(
        block_seqno, timestamp, rand_seed, parent_hash, msgs);

    auto stored0 = ew::global_evm_state().get_transaction_copy(tx0->hash);
    auto receipt0 = ew::global_evm_state().get_receipt_copy(tx0->hash);
    auto stored2 = ew::global_evm_state().get_transaction_copy(tx2->hash);
    auto block = ew::global_evm_state().get_block_copy(block_seqno);
    bool block_ok = ew::global_evm_state().has_block(block_seqno) &&
                    block.transaction_hashes.size() == 1 &&
                    block.transaction_hashes[0] == tx0->hash &&
                    block.gas_used == 21'000;
    bool tx0_ok = stored0 && stored0->tx_index == 0 &&
                  receipt0 && receipt0->tx_index == 0 &&
                  receipt0->cumulative_gas_used == 21'000;
    bool suffix_dropped = !stored2.has_value() &&
                          ew::stashed_side_effects_count() == before_stash_count;

    if (applied != 1 || !tx0_ok || !block_ok || !suffix_dropped) {
        tprintf("  FAILED: applied=%zu tx0_ok=%d block_ok=%d suffix_dropped=%d\n",
                applied, tx0_ok, block_ok, suffix_dropped);
        return;
    }
    tprintf("  PASSED (missing middle side-effect publishes exact prefix only)\n");
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    tprintf("EVM Workchain — compute-phase purity (P1 audit closure) tests\n");
    tprintf("==============================================================\n\n");

    // Bring up g_evm_state + the dispatch handler. Snapshot compute uses
    // per-call trie calculators; the post-accept apply layer still reads
    // global_evm_state(), so init must run before the tests.
    ew::init_evm_workchain();

    test_same_block_validated_twice_is_idempotent();
    test_collator_validator_agree_on_state_root();
    test_fork_order_independence();
    test_restart_validator_matches_collator();
    test_post_accept_missing_side_effect_keeps_prefix_indices();

    tprintf("\nTotal: passed=%d, failures=%d, skips=%d\n",
            g_passes.load(), g_failures.load(), g_skips.load());
    return g_failures.load() == 0 ? 0 : 1;
}
