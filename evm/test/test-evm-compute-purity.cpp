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
      5. post_accept_missing_side_effect_withholds_partial_block
      6. block_hash_history_roundtrip_and_read_header
      7. cp_new_data_declared_root_not_recomputed_per_tx
      8. same_block_second_evm_tx_is_rejected_without_accumulator
      9. cp_new_data_rejects_legacy_layouts
      10. post_accept_recovers_persisted_side_effect_after_memory_loss
      11. post_accept_replays_side_effect_after_stash_and_db_loss
      12. chain_id_env_ignored_in_production_build
      13. pending_side_effect_db_prunes_ttl_and_cap
      14. post_accept_parser_rejects_special_cells
      15. post_accept_rejects_gas_used_overflow
      16. evm_state_size_budget_rejects_oversized_full_root
      17. invalid_tx_prevalidation_runs_before_state_budget

    Build target: test-evm-compute-purity (see evm/test/CMakeLists.txt)
*/

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unistd.h>

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
#include "evm/rpc/cache-db.h"

#include "vm/cells/CellBuilder.h"
#include "vm/cells/Cell.h"
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

// Build a `cp.new_data` v4 cell wrapping the supplied state_root cell. Same
// layout that `run_evm_compute_phase_snapshot` itself emits (and that the
// genesis builder produces): magic + version + has_root + ^state_root
// + eth_state_root + has_cache=0 + has_block_hashes=0
// + reserved_accumulator=0.
static td::Ref<vm::Cell> wrap_state_root_with_declared_eth_root(
    td::Ref<vm::Cell> state_root,
    const evmc::bytes32& eth_state_root) {
    vm::CellBuilder cb;
    cb.store_long(static_cast<long long>(ew::kEvmAccountMagic), ew::kEvmMagicBits);
    cb.store_long(ew::kCpNewDataSchemaVersion, 8);
    if (state_root.not_null()) {
        cb.store_long(1, 1);
        cb.store_ref(state_root);
    } else {
        cb.store_long(0, 1);
    }
    cb.store_bytes(reinterpret_cast<const char*>(eth_state_root.bytes), 32);
    cb.store_long(0, 1);
    cb.store_long(0, 1);
    cb.store_long(0, 1);
    return cb.finalize();
}

static td::Ref<vm::Cell> wrap_state_root_as_account_data(td::Ref<vm::Cell> state_root) {
    return wrap_state_root_with_declared_eth_root(
        state_root,
        compute_eth_state_root_from_cell(state_root));
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
    uint64_t gas_limit = 50'000,
    uint64_t chain_id = ew::kEvmChainId) {

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
    txn.chain_id = chain_id;
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
    txn.set_v(intx::uint256{chain_id * 2 + 35 + recovery_id});

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
    std::shared_ptr<ew::EvmBlockSideEffects> fx;
    std::string vm_log;
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
    return ComputeOutcome{ok, cp.success, cp.skip_reason, cp.new_data,
                          cp.evm_side_effects, cp.vm_log};
}

// Compare two non-null cells by their canonical hash.
static bool cells_hash_equal(const td::Ref<vm::Cell>& a, const td::Ref<vm::Cell>& b) {
    if (a.is_null() || b.is_null()) return false;
    return a->get_hash() == b->get_hash();
}

static std::optional<evmc::bytes32> block_hash_from_account_data(
    const td::Ref<vm::Cell>& account_data,
    uint64_t block_number) {
    td::Ref<vm::Cell> state_root;
    evmc::bytes32 eth_state_root{};
    td::Ref<vm::Cell> rpc_cache_root;
    td::Ref<vm::Cell> block_hashes_root;
    if (!ew::decode_cp_new_data(account_data, state_root, eth_state_root,
                                rpc_cache_root, true, &block_hashes_root)) {
        return std::nullopt;
    }
    ew::CellEvmState history;
    if (!history.load_block_hashes_from_cell(block_hashes_root)) {
        return std::nullopt;
    }
    return history.canonical_hash(block_number);
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
// Test 5 — post_accept_missing_side_effect_withholds_partial_block
// ---------------------------------------------------------------------------
//
// If the deferred side-effect cache misses in the middle of an accepted
// block, post-accept must not compress later records onto the missing
// tx_index, and must not publish a partial block summary. Withhold all public
// records for that block and mark the known tx hashes as indexing-incomplete.

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

static void test_post_accept_missing_side_effect_withholds_partial_block() {
    tprintf("[TEST] post_accept_missing_side_effect_withholds_partial_block\n");

    ew::clear_stashed_side_effects_for_tests();
    ew::reset_evm_post_accept_health_for_tests();

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
    auto receipt2 = ew::global_evm_state().get_receipt_copy(tx2->hash);
    auto health = ew::evm_post_accept_health();
    bool no_partial_indexes = !stored0 && !receipt0 && !stored2 && !receipt2 &&
                              !ew::global_evm_state().has_block(block_seqno);
    bool incomplete_marked = health.missing_side_effects == 1 &&
                             health.incomplete_indexed_transactions == 3 &&
                             health.incomplete_indexed_blocks == 1;
    bool side_effects_preserved = ew::stashed_side_effects_count() == 2;

    if (applied != 0 || !no_partial_indexes ||
        !incomplete_marked || !side_effects_preserved) {
        tprintf("  FAILED: applied=%zu no_partial=%d incomplete=%d preserved=%d "
                "missing=%llu incomplete_txs=%llu incomplete_blocks=%llu stashed=%zu\n",
                applied, no_partial_indexes, incomplete_marked,
                side_effects_preserved,
                static_cast<unsigned long long>(health.missing_side_effects),
                static_cast<unsigned long long>(health.incomplete_indexed_transactions),
                static_cast<unsigned long long>(health.incomplete_indexed_blocks),
                ew::stashed_side_effects_count());
        return;
    }
    ew::clear_stashed_side_effects_for_tests();
    ew::reset_evm_post_accept_health_for_tests();
    tprintf("  PASSED (missing middle side-effect withholds partial block indexes)\n");
}

// ---------------------------------------------------------------------------
// Test 6 — block_hash_history_roundtrip_and_read_header
// ---------------------------------------------------------------------------
//
// BLOCKHASH walks backward from the current block's parent hash through
// read_header(). The serialized cp.new_data history must survive reload and
// synthesize parent links from the canonical hash map.

static void test_block_hash_history_roundtrip_and_read_header() {
    tprintf("[TEST] block_hash_history_roundtrip_and_read_header\n");

    ew::CellEvmState state;
    evmc::bytes32 h10{};
    evmc::bytes32 h11{};
    h10.bytes[31] = 0x10;
    h11.bytes[31] = 0x11;
    state.canonize_block(10, h10);
    state.canonize_block(11, h11);

    auto root = state.serialize_block_hashes_to_cell();
    ew::CellEvmState loaded;
    bool loaded_ok = loaded.load_block_hashes_from_cell(root);
    auto canon10 = loaded.canonical_hash(10);
    auto header11 = loaded.read_header(11, h11);
    bool ok = loaded_ok &&
              canon10 && *canon10 == h10 &&
              header11 && header11->parent_hash == h10;

    if (!ok) {
        tprintf("  FAILED: loaded_ok=%d canon10=%d header11=%d\n",
                loaded_ok,
                canon10.has_value(),
                header11.has_value());
        return;
    }
    tprintf("  PASSED (serialized block-hash history supports read_header)\n");
}

// ---------------------------------------------------------------------------
// Test 7 — cp_new_data_declared_root_not_recomputed_per_tx
// ---------------------------------------------------------------------------
//
// Full eth_state_root verification is still available to strict decoders, but
// the hot compute path must not run a full trie recomputation before every tx.
// A deliberately stale declared root should fail strict decode while snapshot
// compute can still execute from the TOS-bound state_root cell.

static void test_cp_new_data_declared_root_not_recomputed_per_tx() {
    tprintf("[TEST] cp_new_data_declared_root_not_recomputed_per_tx\n");

    evmc::address recipient{};
    recipient.bytes[19] = 0x76;

    auto tx = make_signed_transfer(/*key_seed=*/0xF50000, /*nonce=*/0, recipient);
    if (!tx) {
        tprintf("  FAILED: could not sign test tx\n");
        return;
    }

    intx::uint256 balance{1};
    for (int i = 0; i < 18; ++i) balance *= intx::uint256{10};
    ew::CellEvmState cs;
    silkworm::Account acct{};
    acct.balance = balance;
    cs.update_account(tx->sender, std::nullopt, acct);

    auto state_root = cs.serialize_to_cell();
    auto declared_root = compute_eth_state_root_from_cell(state_root);
    declared_root.bytes[0] ^= 0x80;
    auto bad_account_data = wrap_state_root_with_declared_eth_root(
        state_root,
        declared_root);

    td::Ref<vm::Cell> decoded_state_root;
    evmc::bytes32 decoded_eth_state_root{};
    td::Ref<vm::Cell> decoded_cache_root;
    bool strict_decoded = ew::decode_cp_new_data(
        bad_account_data,
        decoded_state_root,
        decoded_eth_state_root,
        decoded_cache_root,
        /*verify_eth_state_root=*/true);

    auto out = run_once(bad_account_data, tx->raw_rlp,
                        /*block_seqno=*/818181,
                        /*timestamp=*/1800000300);
    if (strict_decoded || !out.ok || !out.success || out.new_data.is_null()) {
        tprintf("  FAILED: strict_decoded=%d ok=%d success=%d new_data=%d\n",
                strict_decoded,
                out.ok,
                out.success,
                out.new_data.not_null());
        return;
    }
    tprintf("  PASSED (compute skips per-tx full root verification; strict decode still rejects)\n");
}

// ---------------------------------------------------------------------------
// Test 8 — same_block_second_evm_tx_is_rejected_without_accumulator
// ---------------------------------------------------------------------------
//
// The old in-account block accumulator made cp.new_data grow with every EVM tx
// in a TOS block. Until a bounded accumulator exists, we conservatively allow
// only one EVM tx per TOS block and reject the second instead of persisting a
// partial or quadratic accumulator.

static void test_same_block_second_evm_tx_is_rejected_without_accumulator() {
    tprintf("[TEST] same_block_second_evm_tx_is_rejected_without_accumulator\n");

    evmc::address recipient{};
    recipient.bytes[19] = 0x75;
    auto tx0 = make_signed_transfer(/*key_seed=*/0xF50001, /*nonce=*/0, recipient);
    auto tx1 = make_signed_transfer(/*key_seed=*/0xF50002, /*nonce=*/0, recipient);
    if (!tx0 || !tx1) {
        tprintf("  FAILED: could not sign test txs\n");
        return;
    }

    intx::uint256 balance{1};
    for (int i = 0; i < 18; ++i) balance *= intx::uint256{10};
    ew::CellEvmState cs;
    silkworm::Account a0{};
    a0.balance = balance;
    cs.update_account(tx0->sender, std::nullopt, a0);
    silkworm::Account a1{};
    a1.balance = balance;
    cs.update_account(tx1->sender, std::nullopt, a1);

    auto account_data = wrap_state_root_as_account_data(cs.serialize_to_cell());
    const uint64_t block_seqno = 777777;
    const uint64_t timestamp = 1800000200;

    auto out0 = run_once(account_data, tx0->raw_rlp, block_seqno, timestamp);
    auto out1 = run_once(out0.new_data, tx1->raw_rlp, block_seqno, timestamp);

    auto persisted_hash = block_hash_from_account_data(out0.new_data, block_seqno);
    bool ok = out0.success && !out1.success &&
              out1.skip_reason == block::ComputePhase::sk_bad_state &&
              out0.fx && !out1.fx &&
              out0.fx->block.transaction_hashes.size() == 1 &&
              out0.fx->block.transaction_hashes[0] == tx0->hash &&
              out0.fx->receipt.tx_index == 0 &&
              out0.fx->receipt.cumulative_gas_used == out0.fx->receipt.gas_used &&
              persisted_hash && *persisted_hash == out0.fx->block.hash;

    if (!ok) {
        tprintf("  FAILED: success=(%d,%d) skip=%d sizes=(%zu,%zu) persisted=%d\n",
                out0.success,
                out1.success,
                out1.skip_reason,
                out0.fx ? out0.fx->block.transaction_hashes.size() : 0,
                out1.fx ? out1.fx->block.transaction_hashes.size() : 0,
                persisted_hash.has_value());
        return;
    }
    tprintf("  PASSED (second same-block EVM tx is rejected without an accumulator)\n");
}

// ---------------------------------------------------------------------------
// Test 9 — cp_new_data_rejects_legacy_layouts
// ---------------------------------------------------------------------------
//
// TOS has not launched mainnet, so cp.new_data has no backwards-compatibility
// decoder. Old unversioned layouts and the removed block-accumulator payload
// must fail closed instead of being interpreted as current v4 state.

static void test_cp_new_data_rejects_legacy_layouts() {
    tprintf("[TEST] cp_new_data_rejects_legacy_layouts\n");

    auto eth_state_root = compute_eth_state_root_from_cell({});
    vm::CellBuilder cb;
    cb.store_long(static_cast<long long>(ew::kEvmAccountMagic), ew::kEvmMagicBits);
    cb.store_long(0, 1);  // old unversioned has_state_root
    cb.store_bytes(reinterpret_cast<const char*>(eth_state_root.bytes), 32);
    cb.store_long(0, 1);  // old has_cache
    cb.store_long(0, 1);  // old has_block_hashes
    cb.store_long(0, 1);  // old has_block_accumulator
    auto old_cell = cb.finalize();

    td::Ref<vm::Cell> state_root;
    evmc::bytes32 decoded_root{};
    td::Ref<vm::Cell> rpc_cache_root;
    bool decoded = ew::decode_cp_new_data(old_cell, state_root, decoded_root,
                                          rpc_cache_root);

    vm::CellBuilder acc_ref_cb;
    auto accumulator_ref = acc_ref_cb.finalize();
    vm::CellBuilder acc_cb;
    acc_cb.store_long(static_cast<long long>(ew::kEvmAccountMagic), ew::kEvmMagicBits);
    acc_cb.store_long(ew::kCpNewDataSchemaVersion, 8);
    acc_cb.store_long(0, 1);  // has_state_root
    acc_cb.store_bytes(reinterpret_cast<const char*>(eth_state_root.bytes), 32);
    acc_cb.store_long(0, 1);  // has_cache
    acc_cb.store_long(0, 1);  // has_block_hashes
    acc_cb.store_long(1, 1);  // removed block accumulator must be rejected
    acc_cb.store_ref(accumulator_ref);
    auto accumulator_cell = acc_cb.finalize();

    bool accumulator_decoded = ew::decode_cp_new_data(
        accumulator_cell, state_root, decoded_root, rpc_cache_root);
    if (decoded || accumulator_decoded) {
        tprintf("  FAILED: decoded legacy cp.new_data (unversioned=%d accumulator=%d)\n",
                decoded,
                accumulator_decoded);
        return;
    }
    tprintf("  PASSED (legacy cp.new_data layouts are rejected)\n");
}

// ---------------------------------------------------------------------------
// Test 10 — post_accept_recovers_persisted_side_effect_after_memory_loss
// ---------------------------------------------------------------------------
//
// The in-memory stash is bounded and process-local. A pending copy in the RPC
// cache DB must let post-accept recover an accepted tx if the memory map was
// cleared before cleanup_applied_external_messages walks BlockData.

static void test_post_accept_recovers_persisted_side_effect_after_memory_loss() {
    tprintf("[TEST] post_accept_recovers_persisted_side_effect_after_memory_loss\n");

    const std::string tmp_root =
        "/tmp/tos-evm-sidefx-pending-" + std::to_string(static_cast<long long>(getpid()));
    std::system(("rm -rf " + tmp_root).c_str());

    auto db_r = ew::EvmRpcCacheDb::open(tmp_root);
    if (db_r.is_error()) {
        tprintf("  FAILED: could not open cache DB: %s\n",
                db_r.error().message().c_str());
        return;
    }
    ew::set_evm_rpc_cache_db(db_r.move_as_ok());

    evmc::address recipient{};
    recipient.bytes[19] = 0x74;
    auto tx = make_signed_transfer(/*key_seed=*/0xF40004, /*nonce=*/0, recipient);
    if (!tx) {
        tprintf("  FAILED: could not sign test tx\n");
        ew::set_evm_rpc_cache_db(nullptr);
        std::system(("rm -rf " + tmp_root).c_str());
        return;
    }
    auto msg = ew::build_evm_external_message(tx->raw_rlp.data(),
                                              tx->raw_rlp.size(),
                                              tx->sender);
    if (msg.is_null()) {
        tprintf("  FAILED: could not build external message\n");
        ew::set_evm_rpc_cache_db(nullptr);
        std::system(("rm -rf " + tmp_root).c_str());
        return;
    }

    const uint64_t block_seqno = 525252;
    const uint64_t timestamp = 1800000100;
    uint8_t rand_seed[32] = {};
    uint8_t parent_hash[32] = {};
    rand_seed[31] = 0x6a;
    parent_hash[31] = 0xb5;

    ew::stash_side_effects(block_seqno, timestamp, rand_seed, parent_hash,
                           tx->hash,
                           make_test_side_effect(*tx, recipient, 22'000, 0x40));
    ew::clear_stashed_side_effects_for_tests();

    std::vector<td::Ref<vm::Cell>> msgs{msg};
    size_t applied = ew::apply_stashed_side_effects_for_messages(
        block_seqno, timestamp, rand_seed, parent_hash, msgs);

    auto stored = ew::global_evm_state().get_transaction_copy(tx->hash);
    auto receipt = ew::global_evm_state().get_receipt_copy(tx->hash);
    auto block = ew::global_evm_state().get_block_copy(block_seqno);
    bool ok = applied == 1 &&
              stored && stored->tx_index == 0 &&
              receipt && receipt->tx_index == 0 &&
              receipt->cumulative_gas_used == 22'000 &&
              ew::global_evm_state().has_block(block_seqno) &&
              block.transaction_hashes.size() == 1 &&
              block.transaction_hashes[0] == tx->hash &&
              block.gas_used == 22'000;

    ew::set_evm_rpc_cache_db(nullptr);
    std::system(("rm -rf " + tmp_root).c_str());

    if (!ok) {
        tprintf("  FAILED: applied=%zu stored=%d receipt=%d block_txs=%zu gas=%llu\n",
                applied,
                stored.has_value(),
                receipt.has_value(),
                block.transaction_hashes.size(),
                static_cast<unsigned long long>(block.gas_used));
        return;
    }
    tprintf("  PASSED (post-accept recovered side effects from pending cache DB)\n");
}

// ---------------------------------------------------------------------------
// Test 11 — post_accept_replays_side_effect_after_stash_and_db_loss
// ---------------------------------------------------------------------------
//
// If both the process-local stash and pending DB are unavailable, post-accept
// can still rebuild RPC side effects from canonical pre-state plus the
// accepted message and block context.

static void test_post_accept_replays_side_effect_after_stash_and_db_loss() {
    tprintf("[TEST] post_accept_replays_side_effect_after_stash_and_db_loss\n");

    ew::set_evm_rpc_cache_db(nullptr);
    ew::clear_stashed_side_effects_for_tests();
    ew::reset_evm_post_accept_health_for_tests();

    evmc::address recipient{};
    recipient.bytes[19] = 0x78;
    auto tx = make_signed_transfer(/*key_seed=*/0xF50005, /*nonce=*/0, recipient);
    if (!tx) {
        tprintf("  FAILED: could not sign replay test tx\n");
        return;
    }
    auto msg = ew::build_evm_external_message(tx->raw_rlp.data(),
                                              tx->raw_rlp.size(),
                                              tx->sender);
    if (msg.is_null()) {
        tprintf("  FAILED: could not build external message\n");
        return;
    }

    intx::uint256 balance{1};
    for (int i = 0; i < 18; ++i) balance *= intx::uint256{10};
    auto pre_account_data =
        make_account_data_with_funded_sender(tx->sender, balance, /*nonce=*/0);

    const uint64_t block_seqno = 626262;
    const uint64_t timestamp = 1800000400;
    uint8_t rand_seed[32] = {};
    uint8_t parent_hash[32] = {};
    rand_seed[31] = 0x7a;
    parent_hash[31] = 0xc5;

    std::vector<td::Ref<vm::Cell>> msgs{msg};
    std::vector<uint64_t> gas_limits{1'000'000};
    size_t applied = ew::apply_stashed_side_effects_for_messages(
        block_seqno, timestamp, rand_seed, parent_hash, msgs, gas_limits,
        pre_account_data);

    auto stored = ew::global_evm_state().get_transaction_copy(tx->hash);
    auto receipt = ew::global_evm_state().get_receipt_copy(tx->hash);
    auto block = ew::global_evm_state().get_block_copy(block_seqno);
    auto health = ew::evm_post_accept_health();
    bool ok = applied == 1 &&
              stored && stored->tx_index == 0 &&
              receipt && receipt->tx_index == 0 &&
              receipt->cumulative_gas_used == receipt->gas_used &&
              ew::global_evm_state().has_block(block_seqno) &&
              block.transaction_hashes.size() == 1 &&
              block.transaction_hashes[0] == tx->hash &&
              health.replayed_side_effects == 1 &&
              health.missing_side_effects == 0 &&
              health.strict_root_failures == 0;

    if (!ok) {
        tprintf("  FAILED: applied=%zu stored=%d receipt=%d block_txs=%zu replayed=%llu missing=%llu strict=%llu\n",
                applied,
                stored.has_value(),
                receipt.has_value(),
                block.transaction_hashes.size(),
                static_cast<unsigned long long>(health.replayed_side_effects),
                static_cast<unsigned long long>(health.missing_side_effects),
                static_cast<unsigned long long>(health.strict_root_failures));
        return;
    }
    tprintf("  PASSED (post-accept replayed side effects without stash or pending DB)\n");
}

// ---------------------------------------------------------------------------
// Test 12 — chain_id_env_ignored_in_production_build
// ---------------------------------------------------------------------------
//
// The production binary must not derive consensus-critical EVM chain_id from
// process-local environment. Devnet/Hive builds opt in with
// TOS_DEVNET_ALLOW_EVM_CHAIN_ID_ENV and keep this test as an explicit skip.

static void test_chain_id_env_ignored_in_production_build() {
    tprintf("[TEST] chain_id_env_ignored_in_production_build\n");
#ifdef TOS_DEVNET_ALLOW_EVM_CHAIN_ID_ENV
    ++g_skips;
    tprintf("  SKIPPED (devnet build intentionally allows TOS_EVM_CHAIN_ID)\n");
#else
    if (ew::current_evm_chain_id() != ew::kEvmChainId) {
        ++g_failures;
        tprintf("  FAILED: current=0x%llx expected=0x%llx\n",
                static_cast<unsigned long long>(ew::current_evm_chain_id()),
                static_cast<unsigned long long>(ew::kEvmChainId));
        return;
    }
    ++g_passes;
    tprintf("  PASSED (TOS_EVM_CHAIN_ID was ignored in this build)\n");
#endif
}

// ---------------------------------------------------------------------------
// Test 13 — pending_side_effect_db_prunes_ttl_and_cap
// ---------------------------------------------------------------------------
//
// Pending side effects are best-effort non-consensus recovery records. They
// must be prunable by block-seqno window and bounded by record count.

static td::Bits256 test_bits256(uint8_t low_byte) {
    td::Bits256 v;
    v.set_zero();
    v.data()[31] = low_byte;
    return v;
}

static td::Ref<vm::Cell> tiny_pending_cell(uint64_t value) {
    vm::CellBuilder cb;
    cb.store_long(static_cast<long long>(value), 64);
    return cb.finalize();
}

static bool pending_present(ew::EvmRpcCacheDb& db,
                            uint64_t seqno,
                            uint64_t timestamp,
                            const td::Bits256& rand_seed,
                            const td::Bits256& parent_hash,
                            const td::Bits256& tx_hash) {
    auto r = db.get_pending_side_effects(seqno, timestamp, rand_seed,
                                         parent_hash, tx_hash);
    return r.is_ok() && r.ok().not_null();
}

static void test_pending_side_effect_db_prunes_ttl_and_cap() {
    tprintf("[TEST] pending_side_effect_db_prunes_ttl_and_cap\n");

    const std::string tmp_root =
        "/tmp/tos-evm-sidefx-prune-" + std::to_string(static_cast<long long>(getpid()));
    std::system(("rm -rf " + tmp_root).c_str());

    auto db_r = ew::EvmRpcCacheDb::open(tmp_root);
    if (db_r.is_error()) {
        ++g_failures;
        tprintf("  FAILED: could not open cache DB: %s\n",
                db_r.error().message().c_str());
        return;
    }
    auto db = db_r.move_as_ok();

    auto rand_seed = test_bits256(0xa1);
    auto parent_hash = test_bits256(0xb2);
    auto put = [&](uint64_t seqno, uint8_t tx_low) {
        return db->put_pending_side_effects(seqno, 1000 + seqno,
                                            rand_seed, parent_hash,
                                            test_bits256(tx_low),
                                            tiny_pending_cell(seqno)).is_ok();
    };

    bool put_ok = put(1, 1) && put(2, 2) && put(3, 3);
    auto ttl_status = db->prune_pending_side_effects(/*keep_from_block_seqno=*/3,
                                                     /*max_records=*/0);
    bool ttl_ok = ttl_status.is_ok() &&
                  !pending_present(*db, 1, 1001, rand_seed, parent_hash, test_bits256(1)) &&
                  !pending_present(*db, 2, 1002, rand_seed, parent_hash, test_bits256(2)) &&
                   pending_present(*db, 3, 1003, rand_seed, parent_hash, test_bits256(3));

    put_ok = put_ok && put(10, 10) && put(11, 11) && put(12, 12);
    auto cap_status = db->prune_pending_side_effects(/*keep_from_block_seqno=*/0,
                                                     /*max_records=*/1);
    int remaining = 0;
    remaining += pending_present(*db, 3, 1003, rand_seed, parent_hash, test_bits256(3)) ? 1 : 0;
    remaining += pending_present(*db, 10, 1010, rand_seed, parent_hash, test_bits256(10)) ? 1 : 0;
    remaining += pending_present(*db, 11, 1011, rand_seed, parent_hash, test_bits256(11)) ? 1 : 0;
    remaining += pending_present(*db, 12, 1012, rand_seed, parent_hash, test_bits256(12)) ? 1 : 0;
    bool cap_ok = cap_status.is_ok() && remaining <= 1;

    auto incomplete_tx = test_bits256(0xd1);
    bool saw_incomplete_tx = false;
    auto put_tx_marker = db->put_incomplete_transaction(incomplete_tx);
    auto has_tx_marker = db->has_incomplete_transaction(incomplete_tx);
    auto walk_tx_marker = db->for_each_incomplete_transaction(
        [&](const td::Bits256& tx_hash) -> td::Status {
            if (std::memcmp(tx_hash.data(), incomplete_tx.data(), 32) == 0) {
                saw_incomplete_tx = true;
            }
            return td::Status::OK();
        });
    auto del_tx_marker = db->delete_incomplete_transaction(incomplete_tx);
    auto has_tx_after_delete = db->has_incomplete_transaction(incomplete_tx);

    bool saw_incomplete_block = false;
    constexpr uint64_t kIncompleteBlock = 424242;
    auto put_block_marker = db->put_incomplete_block(kIncompleteBlock);
    auto has_block_marker = db->has_incomplete_block(kIncompleteBlock);
    auto walk_block_marker = db->for_each_incomplete_block(
        [&](uint64_t block_number) -> td::Status {
            if (block_number == kIncompleteBlock) saw_incomplete_block = true;
            return td::Status::OK();
        });
    auto del_block_marker = db->delete_incomplete_block(kIncompleteBlock);
    auto has_block_after_delete = db->has_incomplete_block(kIncompleteBlock);
    bool incomplete_marker_ok =
        put_tx_marker.is_ok() &&
        has_tx_marker.is_ok() && has_tx_marker.ok() &&
        walk_tx_marker.is_ok() && saw_incomplete_tx &&
        del_tx_marker.is_ok() &&
        has_tx_after_delete.is_ok() && !has_tx_after_delete.ok() &&
        put_block_marker.is_ok() &&
        has_block_marker.is_ok() && has_block_marker.ok() &&
        walk_block_marker.is_ok() && saw_incomplete_block &&
        del_block_marker.is_ok() &&
        has_block_after_delete.is_ok() && !has_block_after_delete.ok();

    db.reset();
    std::system(("rm -rf " + tmp_root).c_str());

    if (!put_ok || !ttl_ok || !cap_ok || !incomplete_marker_ok) {
        ++g_failures;
        tprintf("  FAILED: put=%d ttl=%d cap=%d remaining=%d incomplete_marker=%d\n",
                put_ok, ttl_ok, cap_ok, remaining, incomplete_marker_ok);
        return;
    }
    ++g_passes;
    tprintf("  PASSED (pending side effects and incomplete markers are durable/bounded)\n");
}

// ---------------------------------------------------------------------------
// Test 14 — post_accept_parser_rejects_special_cells
// ---------------------------------------------------------------------------

static td::Ref<vm::Cell> make_library_special_cell_for_post_accept_test() {
    unsigned char zero_hash[32] = {};
    vm::CellBuilder cb;
    cb.store_long(static_cast<long long>(vm::Cell::SpecialType::Library), 8);
    cb.store_bytes(zero_hash, sizeof(zero_hash));
    return cb.finalize(true);
}

static void test_post_accept_parser_rejects_special_cells() {
    tprintf("[TEST] post_accept_parser_rejects_special_cells\n");

    ew::reset_evm_post_accept_health_for_tests();
    uint8_t rand_seed[32] = {};
    uint8_t parent_hash[32] = {};
    std::vector<td::Ref<vm::Cell>> msgs{
        make_library_special_cell_for_post_accept_test()};

    size_t applied = ew::apply_stashed_side_effects_for_messages(
        737373, 1800000500, rand_seed, parent_hash, msgs);
    auto health = ew::evm_post_accept_health();
    bool ok = applied == 0 &&
              health.malformed_messages == 1 &&
              health.malformed_special_cell_messages >= 1;

    if (!ok) {
        ++g_failures;
        tprintf("  FAILED: applied=%zu malformed=%llu special=%llu\n",
                applied,
                static_cast<unsigned long long>(health.malformed_messages),
                static_cast<unsigned long long>(health.malformed_special_cell_messages));
        return;
    }
    ++g_passes;
    tprintf("  PASSED (special post-accept message cell rejected without crash)\n");
}

// ---------------------------------------------------------------------------
// Test 15 — post_accept_rejects_gas_used_overflow
// ---------------------------------------------------------------------------

static void test_post_accept_rejects_gas_used_overflow() {
    tprintf("[TEST] post_accept_rejects_gas_used_overflow\n");

    ew::clear_stashed_side_effects_for_tests();
    ew::reset_evm_post_accept_health_for_tests();

    evmc::address recipient{};
    recipient.bytes[19] = 0x88;
    auto tx0 = make_signed_transfer(/*key_seed=*/0xF60001, /*nonce=*/0, recipient);
    auto tx1 = make_signed_transfer(/*key_seed=*/0xF60002, /*nonce=*/0, recipient);
    if (!tx0 || !tx1) {
        ++g_failures;
        tprintf("  FAILED: could not sign gas overflow test txs\n");
        return;
    }
    auto msg0 = ew::build_evm_external_message(tx0->raw_rlp.data(), tx0->raw_rlp.size(), tx0->sender);
    auto msg1 = ew::build_evm_external_message(tx1->raw_rlp.data(), tx1->raw_rlp.size(), tx1->sender);

    const uint64_t block_seqno = 838383;
    const uint64_t timestamp = 1800000600;
    uint8_t rand_seed[32] = {};
    uint8_t parent_hash[32] = {};
    rand_seed[31] = 0x33;
    parent_hash[31] = 0x44;

    auto fx0 = make_test_side_effect(*tx0, recipient, 60, 0x51);
    auto fx1 = make_test_side_effect(*tx1, recipient, 60, 0x52);
    fx0.block.gas_limit = 100;
    fx1.block.gas_limit = 100;

    ew::stash_side_effects(block_seqno, timestamp, rand_seed, parent_hash, tx0->hash, fx0);
    ew::stash_side_effects(block_seqno, timestamp, rand_seed, parent_hash, tx1->hash, fx1);

    std::vector<td::Ref<vm::Cell>> msgs{msg0, msg1};
    size_t applied = ew::apply_stashed_side_effects_for_messages(
        block_seqno, timestamp, rand_seed, parent_hash, msgs);
    auto health = ew::evm_post_accept_health();
    bool ok = applied == 0 &&
              health.strict_root_failures == 1 &&
              !ew::global_evm_state().get_receipt_copy(tx0->hash) &&
              !ew::global_evm_state().get_receipt_copy(tx1->hash);

    if (!ok) {
        ++g_failures;
        tprintf("  FAILED: applied=%zu strict=%llu receipt0=%d receipt1=%d\n",
                applied,
                static_cast<unsigned long long>(health.strict_root_failures),
                ew::global_evm_state().get_receipt_copy(tx0->hash).has_value(),
                ew::global_evm_state().get_receipt_copy(tx1->hash).has_value());
        return;
    }
    ++g_passes;
    tprintf("  PASSED (post-accept rejects cumulative gas overflow/limit breach)\n");
}

// ---------------------------------------------------------------------------
// Test 16 — evm_state_size_budget_rejects_oversized_full_root
// ---------------------------------------------------------------------------

static void test_evm_state_size_budget_rejects_oversized_full_root() {
    tprintf("[TEST] evm_state_size_budget_rejects_oversized_full_root\n");

    ew::EvmState mem_state;
    for (uint8_t i = 0; i < 5; ++i) {
        evmc::address addr{};
        addr.bytes[19] = i + 1;
        mem_state.seed_account(addr, intx::uint256{1}, 0);
    }

    auto mem_stats = ew::estimate_evm_state_size_for_full_root(
        mem_state, /*max_accounts=*/4, /*max_storage_slots=*/100);

    auto cell_backend = std::make_unique<ew::CellEvmState>();
    auto* raw_cell_backend = cell_backend.get();
    ew::EvmState cell_state(std::move(cell_backend));
    evmc::address cell_addr{};
    cell_addr.bytes[19] = 0xAA;
    cell_state.seed_account(cell_addr, intx::uint256{1}, 0);
    {
        std::unique_lock lock(cell_state.mutex());
        for (uint8_t i = 0; i < 3; ++i) {
            evmc::bytes32 slot{};
            evmc::bytes32 value{};
            slot.bytes[31] = i + 1;
            value.bytes[31] = i + 11;
            raw_cell_backend->update_storage(cell_addr, /*incarnation=*/0,
                                             slot, evmc::bytes32{}, value);
        }
    }
    auto cell_stats = ew::estimate_evm_state_size_for_full_root(
        cell_state, /*max_accounts=*/10, /*max_storage_slots=*/2);

    bool ok = mem_stats.exceeded && !mem_stats.malformed && mem_stats.accounts == 5 &&
              cell_stats.exceeded && !cell_stats.malformed &&
              cell_stats.accounts == 1 && cell_stats.storage_slots == 3;
    if (!ok) {
        ++g_failures;
        tprintf("  FAILED: mem(accounts=%zu storage=%zu exceeded=%d malformed=%d) "
                "cell(accounts=%zu storage=%zu exceeded=%d malformed=%d)\n",
                mem_stats.accounts, mem_stats.storage_slots,
                mem_stats.exceeded, mem_stats.malformed,
                cell_stats.accounts, cell_stats.storage_slots,
                cell_stats.exceeded, cell_stats.malformed);
        return;
    }
    ++g_passes;
    tprintf("  PASSED (full-root state-size budget fails closed for memory and cell state)\n");
}

// ---------------------------------------------------------------------------
// Test 17 — invalid_tx_prevalidation_runs_before_state_budget
// ---------------------------------------------------------------------------

static void test_invalid_tx_prevalidation_runs_before_state_budget() {
    tprintf("[TEST] invalid_tx_prevalidation_runs_before_state_budget\n");

    evmc::address recipient{};
    recipient.bytes[19] = 0x77;
    auto tx = make_signed_transfer(/*key_seed=*/0xF70001, /*nonce=*/0,
                                   recipient, intx::uint256{1},
                                   /*gas_limit=*/50'000,
                                   /*chain_id=*/ew::kEvmChainId + 1);
    if (!tx) {
        ++g_failures;
        tprintf("  FAILED: could not sign wrong-chain tx\n");
        return;
    }

    auto account_data = make_account_data_with_funded_sender(
        tx->sender, intx::uint256{1'000'000'000'000'000'000ULL}, 0);
    auto out = run_once(account_data, tx->raw_rlp);

    bool ok = out.ok &&
              !out.success &&
              !out.fx &&
              out.skip_reason == block::ComputePhase::sk_bad_state &&
              out.vm_log == "wrong chain id";
    if (!ok) {
        ++g_failures;
        tprintf("  FAILED: ok=%d success=%d fx=%d skip=%d log='%s'\n",
                out.ok, out.success, out.fx ? 1 : 0, out.skip_reason,
                out.vm_log.c_str());
        return;
    }
    ++g_passes;
    tprintf("  PASSED (wrong-chain tx rejected by cheap prevalidation)\n");
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
#ifndef TOS_DEVNET_ALLOW_EVM_CHAIN_ID_ENV
    setenv("TOS_EVM_CHAIN_ID", "0xc72dd9d5e883e", 1);
#endif
    ew::init_evm_workchain();
#ifndef TOS_DEVNET_ALLOW_EVM_CHAIN_ID_ENV
    unsetenv("TOS_EVM_CHAIN_ID");
#endif

    test_same_block_validated_twice_is_idempotent();
    test_collator_validator_agree_on_state_root();
    test_fork_order_independence();
    test_restart_validator_matches_collator();
    test_post_accept_missing_side_effect_withholds_partial_block();
    test_block_hash_history_roundtrip_and_read_header();
    test_cp_new_data_declared_root_not_recomputed_per_tx();
    test_same_block_second_evm_tx_is_rejected_without_accumulator();
    test_cp_new_data_rejects_legacy_layouts();
    test_post_accept_recovers_persisted_side_effect_after_memory_loss();
    test_post_accept_replays_side_effect_after_stash_and_db_loss();
    test_chain_id_env_ignored_in_production_build();
    test_pending_side_effect_db_prunes_ttl_and_cap();
    test_post_accept_parser_rejects_special_cells();
    test_post_accept_rejects_gas_used_overflow();
    test_evm_state_size_budget_rejects_oversized_full_root();
    test_invalid_tx_prevalidation_runs_before_state_budget();

    tprintf("\nTotal: passed=%d, failures=%d, skips=%d\n",
            g_passes.load(), g_failures.load(), g_skips.load());
    return g_failures.load() == 0 ? 0 : 1;
}
