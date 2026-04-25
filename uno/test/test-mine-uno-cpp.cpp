/*
    Uno Workchain — MineUno C++ codec + apply round-trip test.

    Pins the Phase 2 `decode_mine_uno` / `encode_mine_uno` / `canonical_mine_uno_hash`
    / `apply_mine_uno` surface against the struct layout in mine_uno.h and the
    Rust mirror in tosctl/uno/src/mine_uno.rs.

    The full STARK-verify integration test requires a real Plonky3 proof
    (produced by `uno_mine_uno_prove`) and a real `UnoState` implementation.
    A shim `FakeMineUnoState` below implements the minimal `UnoState`
    interface needed by `apply_mine_uno`'s state-mutation path — it wires up
    `mine_epoch` / `mine_remaining` and tracks commitments in a vector.

    Tests:
      1. test_canonical_hash_determinism     — byte-stable hash over wire preimage
      2. test_encode_decode_round_trip       — full BoC round-trip
      3. test_decode_rejects_bad_kind        — tx_kind != 0x02 rejected
      4. test_decode_rejects_truncated       — short inline header rejected
      5. test_apply_chain_checks_epoch_race  — epoch mismatch rejected
      6. test_apply_chain_checks_remaining_race — remaining mismatch rejected
      7. test_apply_chain_checks_halving     — wrong value_nano rejected
      8. test_apply_chain_checks_conservation — broken remaining_post rejected
      9. test_apply_chain_checks_bad_kind    — tx_kind != 0x02 rejected
     10. test_apply_success_state_mutation   — full happy path (with a bogus
         proof blob that the FFI verify rejects; state therefore is NOT
         mutated and we assert exactly that invariant)

    Test 7 (AIR-real-proof verify) lives in the Rust `mine_genesis_golden`
    integration test; covering it from C++ additionally requires constructing
    an `UnoWitness` / `prove_mine_uno` path not exposed to this TU.

    Build target: test-mine-uno-cpp (see uno/test/CMakeLists.txt)
*/

#include <array>
#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <variant>

#include "td/utils/Slice.h"
#include "td/utils/UInt.h"
#include "td/utils/buffer.h"
#include "vm/boc.h"
#include "vm/cells/Cell.h"
#include "vm/cells/CellSlice.h"

#include "uno/core/compute-phase.h"
#include "uno/core/mine_constants.h"
#include "uno/core/mine_uno.h"

// ---------------------------------------------------------------------------
// Tracked-printf harness (identical to test-uno-mine-loader.cpp)
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

// ---------------------------------------------------------------------------
// Minimal UnoState shim for apply_mine_uno drive
// ---------------------------------------------------------------------------

namespace uw = uno_workchain;

class FakeMineUnoState : public uw::UnoState {
  public:
    uint32_t epoch_{0};
    uint64_t remaining_{uw::kMineSupplyNano};
    std::array<uint8_t, 32> target_{};
    std::vector<td::Bits256> commitments_;
    std::vector<uint16_t> filter_tags_;
    uint64_t stats_fee_{0};
    uint64_t stats_notes_{0};

    uint32_t chain_id_{0xDEAD'BEEF};
    uint64_t seqno_{0};

    FakeMineUnoState() {
        std::memcpy(target_.data(), uw::kInitMineTargetBE, 32);
    }

    bool anchor_window_contains(const td::Bits256&) const override { return false; }
    bool nullifier_is_spent(const td::Bits256&) const override { return false; }
    void append_commitment(const td::Bits256& cm) override { commitments_.push_back(cm); }
    void insert_nullifier(const td::Bits256&) override {}
    void accumulate_filter_tag(uint16_t tag) override { filter_tags_.push_back(tag); }
    void bump_stats(uint64_t fee, uint64_t d) override {
        stats_fee_ += fee;
        stats_notes_ += d;
    }
    td::Ref<vm::Cell> serialize_to_cell() const override { return {}; }

    uint32_t expected_chain_id() const override    { return chain_id_; }
    uint64_t current_block_seqno() const override  { return seqno_; }
    uint32_t expiry_window_blocks() const override { return 1024; }
    uint64_t min_fee_nano() const override         { return 0; }
    uint64_t fee_per_byte_nano() const override    { return 0; }
    uint64_t fee_per_spend_nano() const override   { return 0; }
    uint64_t fee_per_output_nano() const override  { return 0; }

    // MineUno overrides
    uint32_t mine_epoch() const noexcept override { return epoch_; }
    uint64_t mine_remaining() const noexcept override { return remaining_; }
    std::array<uint8_t, 32> mine_target() const noexcept override { return target_; }
    uint32_t last_solve_ts() const noexcept override { return last_solve_ts_; }
    void advance_mine_state(uint64_t new_remaining,
                            uint32_t gen_utime) noexcept override {
        epoch_ += 1;
        remaining_ = new_remaining;
        last_solve_ts_ = gen_utime;
    }

    uint32_t last_solve_ts_{0};
};

// ---------------------------------------------------------------------------
// Fixture constructors
// ---------------------------------------------------------------------------

static uw::MineUno make_genesis_mine_tx() {
    uw::MineUno tx;
    tx.tx_kind   = uw::kTxKindMineUno;
    tx.version   = uw::kMineUnoVersion;
    tx.scheme_id = uw::kSchemeIdV1;
    tx.chain_id  = 0xDEAD'BEEF;
    tx.public_inputs.epoch         = 0;
    std::memcpy(tx.public_inputs.target.data(), uw::kInitMineTargetBE, 32);
    tx.public_inputs.value_nano    = uw::kInitMineReward;
    tx.public_inputs.output_cm.fill(0xEE);
    tx.public_inputs.remaining_pre  = uw::kMineSupplyNano;
    tx.public_inputs.remaining_post = uw::kMineSupplyNano - uw::kInitMineReward;
    return tx;
}

// Build a syntactically-valid proof blob: [u32 LE proof_len][dummy_proof][96 B PI].
// The bytes are NOT a real Plonky3 STARK proof — `uno_mine_uno_verify` will
// reject them at decode time with ProofDecodeFailed. That is exactly what we
// want for the chain-state-only tests below: `apply_mine_uno` must return
// `BadPlonky3Proof` and leave state unchanged.
static std::vector<uint8_t> make_dummy_proof_blob() {
    std::vector<uint8_t> blob;
    const uint32_t proof_len = 32;   // arbitrary; garbage bytes
    blob.resize(4 + proof_len + 96, 0);
    blob[0] = proof_len & 0xFF;
    blob[1] = (proof_len >> 8) & 0xFF;
    blob[2] = (proof_len >> 16) & 0xFF;
    blob[3] = (proof_len >> 24) & 0xFF;
    // Leave the rest zero.
    return blob;
}

// ---------------------------------------------------------------------------
// Test 1 — canonical_mine_uno_hash determinism
// ---------------------------------------------------------------------------

static void test_canonical_hash_determinism() {
    tprintf("[TEST] test_canonical_hash_determinism\n");
    auto tx = make_genesis_mine_tx();
    tx.proof_blob = make_dummy_proof_blob();
    auto h1 = uw::canonical_mine_uno_hash(tx);
    auto h2 = uw::canonical_mine_uno_hash(tx);
    if (h1 != h2) {
        tprintf("  FAILED: canonical_mine_uno_hash is not stable across calls\n");
        return;
    }
    // Changing any header field must change the hash.
    auto tx2 = tx;
    tx2.public_inputs.epoch = 1;
    auto h3 = uw::canonical_mine_uno_hash(tx2);
    if (h1 == h3) {
        tprintf("  FAILED: epoch perturbation did not change hash\n");
        return;
    }
    // K-mine-tx-hash-binds-proof: two MineUnos that share a header but
    // carry different proof blobs MUST hash differently — otherwise
    // mempool / RPC tx identity collides between a valid and an invalid
    // proof for the same public inputs.
    auto tx_other_proof = tx;
    tx_other_proof.proof_blob[5] ^= 0xFF;  // flip a byte in the proof
    auto h4 = uw::canonical_mine_uno_hash(tx_other_proof);
    if (h1 == h4) {
        tprintf("  FAILED: proof perturbation did not change hash — "
                "tx hash is not bound to proof bytes\n");
        return;
    }
    tprintf("  PASSED (hash stable; distinct on header AND proof perturbation)\n");
}

// ---------------------------------------------------------------------------
// Test 2 — encode / decode round-trip (full BoC)
// ---------------------------------------------------------------------------

static void test_encode_decode_round_trip() {
    tprintf("[TEST] test_encode_decode_round_trip\n");
    auto tx = make_genesis_mine_tx();
    auto blob = make_dummy_proof_blob();

    auto boc_r = uw::encode_mine_uno_to_boc(
        tx, td::Slice(reinterpret_cast<const char*>(blob.data()), blob.size()));
    if (boc_r.is_error()) {
        tprintf("  FAILED: encode_mine_uno_to_boc error: %s\n",
                boc_r.error().message().c_str());
        return;
    }
    auto buf = boc_r.move_as_ok();

    auto decoded = uw::decode_mine_uno_bytes(buf.as_slice());
    if (auto* err = std::get_if<uw::MineUnoDecodeError>(&decoded)) {
        tprintf("  FAILED: decode_mine_uno_bytes error: %s\n", err->reason.c_str());
        return;
    }
    auto& dtx = std::get<uw::MineUno>(decoded);

    if (dtx.tx_kind   != tx.tx_kind)   { tprintf("  FAILED: tx_kind mismatch\n");   return; }
    if (dtx.version   != tx.version)   { tprintf("  FAILED: version mismatch\n");   return; }
    if (dtx.scheme_id != tx.scheme_id) { tprintf("  FAILED: scheme_id mismatch\n"); return; }
    if (dtx.chain_id  != tx.chain_id)  { tprintf("  FAILED: chain_id mismatch\n");  return; }
    if (dtx.public_inputs.epoch          != tx.public_inputs.epoch)          { tprintf("  FAILED: epoch\n");          return; }
    if (dtx.public_inputs.target         != tx.public_inputs.target)         { tprintf("  FAILED: target\n");         return; }
    if (dtx.public_inputs.value_nano     != tx.public_inputs.value_nano)     { tprintf("  FAILED: value_nano\n");     return; }
    if (dtx.public_inputs.output_cm      != tx.public_inputs.output_cm)      { tprintf("  FAILED: output_cm\n");      return; }
    if (dtx.public_inputs.remaining_pre  != tx.public_inputs.remaining_pre)  { tprintf("  FAILED: remaining_pre\n");  return; }
    if (dtx.public_inputs.remaining_post != tx.public_inputs.remaining_post) { tprintf("  FAILED: remaining_post\n"); return; }
    if (dtx.proof_blob.size() != blob.size())                                { tprintf("  FAILED: proof_blob size\n"); return; }
    if (std::memcmp(dtx.proof_blob.data(), blob.data(), blob.size()) != 0)   { tprintf("  FAILED: proof_blob bytes\n"); return; }

    // Canonical hash round-trips too. The pre-encode `tx` has an empty
    // proof_blob (the proof is supplied to encode_mine_uno via a
    // separate slice), but the post-decode `dtx` has it populated from
    // the chunk tree. Mirror that here so both sides hash the same
    // `(header, proof)` pair.
    auto tx_with_proof = tx;
    tx_with_proof.proof_blob = blob;
    if (uw::canonical_mine_uno_hash(tx_with_proof) != uw::canonical_mine_uno_hash(dtx)) {
        tprintf("  FAILED: canonical hash diverges across encode/decode\n");
        return;
    }
    tprintf("  PASSED (full BoC round-trip + canonical hash stable)\n");
}

// ---------------------------------------------------------------------------
// Test 3 — decode rejects bad tx_kind byte
// ---------------------------------------------------------------------------

static void test_decode_rejects_bad_kind() {
    tprintf("[TEST] test_decode_rejects_bad_kind\n");
    auto tx = make_genesis_mine_tx();
    tx.tx_kind = 0x01;   // spoof as Transfer
    auto blob = make_dummy_proof_blob();
    auto boc_r = uw::encode_mine_uno_to_boc(
        tx, td::Slice(reinterpret_cast<const char*>(blob.data()), blob.size()));
    if (!boc_r.is_error()) {
        // encode should reject tx_kind != 0x02
        tprintf("  FAILED: encode accepted tx_kind=0x01 (should reject)\n");
        return;
    }
    tprintf("  PASSED (encode rejected tx_kind != 0x02)\n");
}

// ---------------------------------------------------------------------------
// Test 4 — decode rejects truncated inline header
// ---------------------------------------------------------------------------

static void test_decode_rejects_truncated() {
    tprintf("[TEST] test_decode_rejects_truncated\n");
    // Craft a BoC with a too-short body. std_boc_deserialize will accept;
    // decode_mine_uno must reject with "short inline header".
    std::vector<uint8_t> tiny(32, 0x00);  // 32 zero bytes — no valid MineUno header fits
    auto decoded = uw::decode_mine_uno_bytes(
        td::Slice(reinterpret_cast<const char*>(tiny.data()), tiny.size()));
    if (std::holds_alternative<uw::MineUno>(decoded)) {
        tprintf("  FAILED: decode_mine_uno_bytes accepted a 32-byte garbage input\n");
        return;
    }
    tprintf("  PASSED (truncated/invalid BoC rejected)\n");
}

// ---------------------------------------------------------------------------
// Test 5 — apply_mine_uno rejects epoch race
// ---------------------------------------------------------------------------

static void test_apply_chain_checks_epoch_race() {
    tprintf("[TEST] test_apply_chain_checks_epoch_race\n");
    FakeMineUnoState state;
    state.epoch_ = 42;   // chain has moved past the proof's epoch
    auto tx = make_genesis_mine_tx();  // public_inputs.epoch = 0
    uint32_t before_epoch = state.epoch_;
    uint64_t before_rem   = state.remaining_;
    auto result = uw::verify_mine_uno_chain_checks(state, tx, /*gen_utime=*/0);
    if (result != uw::VerifyResult::EpochRaceDetected) {
        tprintf("  FAILED: verify returned %s; expected EpochRaceDetected\n",
                uw::verify_result_name(result));
        return;
    }
    if (state.epoch_ != before_epoch || state.remaining_ != before_rem) {
        tprintf("  FAILED: epoch race leaked state mutation\n");
        return;
    }
    tprintf("  PASSED (epoch race rejected; state unchanged)\n");
}

// ---------------------------------------------------------------------------
// Test 6 — apply_mine_uno rejects remaining race
// ---------------------------------------------------------------------------

static void test_apply_chain_checks_remaining_race() {
    tprintf("[TEST] test_apply_chain_checks_remaining_race\n");
    FakeMineUnoState state;
    state.remaining_ = uw::kMineSupplyNano - 1;   // already drained 1 nano-UNO
    auto tx = make_genesis_mine_tx();             // tx thinks remaining_pre = full supply
    auto result = uw::verify_mine_uno_chain_checks(state, tx, /*gen_utime=*/0);
    if (result != uw::VerifyResult::RemainingRaceDetected) {
        tprintf("  FAILED: verify returned %s; expected RemainingRaceDetected\n",
                uw::verify_result_name(result));
        return;
    }
    tprintf("  PASSED (remaining race rejected)\n");
}

// ---------------------------------------------------------------------------
// Test 7 — apply_mine_uno rejects wrong halving reward
// ---------------------------------------------------------------------------

static void test_apply_chain_checks_halving() {
    tprintf("[TEST] test_apply_chain_checks_halving\n");
    FakeMineUnoState state;
    auto tx = make_genesis_mine_tx();
    tx.public_inputs.value_nano = uw::kInitMineReward + 1;   // off by 1
    tx.public_inputs.remaining_post = tx.public_inputs.remaining_pre - tx.public_inputs.value_nano;
    auto result = uw::verify_mine_uno_chain_checks(state, tx, /*gen_utime=*/0);
    if (result != uw::VerifyResult::InvalidHalvingReward) {
        tprintf("  FAILED: verify returned %s; expected InvalidHalvingReward\n",
                uw::verify_result_name(result));
        return;
    }
    tprintf("  PASSED (wrong reward rejected)\n");
}

// ---------------------------------------------------------------------------
// Test 8 — apply_mine_uno rejects broken conservation
// ---------------------------------------------------------------------------

static void test_apply_chain_checks_conservation() {
    tprintf("[TEST] test_apply_chain_checks_conservation\n");
    FakeMineUnoState state;
    auto tx = make_genesis_mine_tx();
    tx.public_inputs.remaining_post += 1;   // tampered
    auto result = uw::verify_mine_uno_chain_checks(state, tx, /*gen_utime=*/0);
    if (result != uw::VerifyResult::BadMineConservation) {
        tprintf("  FAILED: verify returned %s; expected BadMineConservation\n",
                uw::verify_result_name(result));
        return;
    }
    tprintf("  PASSED (broken conservation rejected)\n");
}

// ---------------------------------------------------------------------------
// Test 9 — apply_mine_uno rejects unknown tx kind
// ---------------------------------------------------------------------------

static void test_apply_chain_checks_bad_kind() {
    tprintf("[TEST] test_apply_chain_checks_bad_kind\n");
    FakeMineUnoState state;
    auto tx = make_genesis_mine_tx();
    tx.tx_kind = 0x99;
    auto result = uw::verify_mine_uno_chain_checks(state, tx, /*gen_utime=*/0);
    if (result != uw::VerifyResult::UnknownTxKind) {
        tprintf("  FAILED: verify returned %s; expected UnknownTxKind\n",
                uw::verify_result_name(result));
        return;
    }
    tprintf("  PASSED (unknown tx_kind rejected)\n");
}

// ---------------------------------------------------------------------------
// Test 10 — apply_mine_uno rejects bogus proof; state is NOT mutated.
// ---------------------------------------------------------------------------

static void test_apply_rejects_bad_proof_no_mutation() {
    tprintf("[TEST] test_apply_rejects_bad_proof_no_mutation\n");
    FakeMineUnoState state;
    auto tx = make_genesis_mine_tx();
    tx.proof_blob = make_dummy_proof_blob();

    uint32_t before_epoch = state.epoch_;
    uint64_t before_rem   = state.remaining_;
    size_t   before_cms   = state.commitments_.size();
    size_t   before_tags  = state.filter_tags_.size();

    auto result = uw::apply_mine_uno(state, tx, /*gen_utime=*/0);
    // After the round-5 reordering, the cheap O(1) PI/header binding check
    // runs BEFORE the expensive FFI verify, so dummy proof bytes paired
    // with a non-matching dummy PI (as constructed by make_dummy_proof_blob)
    // are rejected as PiHeaderMismatch instead of BadPlonky3Proof. Either
    // is correct — both reject without state mutation, which is what the
    // verify-before-mutate invariant actually cares about.
    if (result != uw::VerifyResult::BadPlonky3Proof &&
        result != uw::VerifyResult::PiHeaderMismatch) {
        tprintf("  FAILED: apply_mine_uno returned %s; expected BadPlonky3Proof "
                "or PiHeaderMismatch (dummy proof must fail before mutation)\n",
                uw::verify_result_name(result));
        return;
    }
    if (state.epoch_ != before_epoch) {
        tprintf("  FAILED: epoch advanced despite proof reject (was %u now %u)\n",
                before_epoch, state.epoch_);
        return;
    }
    if (state.remaining_ != before_rem) {
        tprintf("  FAILED: remaining changed despite proof reject\n");
        return;
    }
    if (state.commitments_.size() != before_cms) {
        tprintf("  FAILED: commitment appended despite proof reject\n");
        return;
    }
    if (state.filter_tags_.size() != before_tags) {
        tprintf("  FAILED: filter tag accumulated despite proof reject\n");
        return;
    }
    tprintf("  PASSED (bad proof rejected; verify-before-mutate invariant held)\n");
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    tprintf("Uno Workchain — MineUno C++ codec + apply test\n");
    tprintf("================================================\n\n");

    test_canonical_hash_determinism();
    test_encode_decode_round_trip();
    test_decode_rejects_bad_kind();
    test_decode_rejects_truncated();
    test_apply_chain_checks_epoch_race();
    test_apply_chain_checks_remaining_race();
    test_apply_chain_checks_halving();
    test_apply_chain_checks_conservation();
    test_apply_chain_checks_bad_kind();
    test_apply_rejects_bad_proof_no_mutation();

    tprintf("\nTotal: passed=%d, failures=%d, skips=%d\n",
            g_passes.load(), g_failures.load(), g_skips.load());
    return g_failures.load() == 0 ? 0 : 1;
}
