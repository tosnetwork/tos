/*
    Uno Workchain — MineUno END-TO-END apply integration test.

    Exercises the full C++ compute-phase code path against a REAL Plonky3
    STARK proof produced live by the in-tree Rust `uno_mine_uno_prove`
    FFI. This is the integration-level counterpart to test-mine-uno-cpp
    (which drives every apply path except the positive
    `apply_mine_uno(...) == VerifyResult::Ok` case because it cannot
    produce a real STARK proof from the plain codec / apply tests).

    Flow:
       1. Port `MineUnoWitness::deterministic_valid(epoch=0, seed)` from
          uno/plonky3-ffi/src/mine_uno_witness.rs and encode to 192 B.
       2. Call `uno_mine_uno_prove` via FFI → owned buffer holding
          `[u32 LE proof_len][proof_bytes][96 B PI bytes]`.
       3. Parse the 96 B PI: PI[0] = epoch (u64 LE), PI[1] = value_nano,
          PI[2..6] (32 B) = output_cm, PI[6..10] = pow_hash (ignored here),
          PI[10] = remaining_pre, PI[11] = remaining_post.
       4. Build a C++ `uno_workchain::MineUno` from those fields + the raw
          proof blob, encode to BoC, decode it back (the same path a
          mempool admission would take).
       5. Drive `apply_mine_uno(state, tx)` against a minimal FakeUnoState
          that starts at epoch=0, remaining=21 M UNO, using a synthetic target
          set just above the proof's PI pow_hash. The deterministic fixture is
          not a real mainnet-difficulty mining result, but this still exercises
          the real pow_hash < target gate.
          Assert `VerifyResult::Ok` AND the state mutations:
             a. state.mine_epoch()      == 1
             b. state.mine_remaining()  == supply - 50 UNO
             c. state.commitments_ has exactly one new entry == output_cm
       6. Resubmit the SAME tx against the (now-mutated) state → assert
          `EpochRaceDetected` (state.mine_epoch() moved past pi.epoch).

    Build target: test-mine-uno-apply-e2e (driven by
    uno/test/integration/test-mine-uno-end-to-end.sh).
*/

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <variant>
#include <vector>

#include "td/utils/Slice.h"
#include "vm/cells/Cell.h"

#include "uno/core/compute-phase.h"
#include "uno/core/mine_constants.h"
#include "uno/core/mine_uno.h"

#include "uno_plonky3_ffi.h"

namespace uw = uno_workchain;

// ---------------------------------------------------------------------------
// FakeMineUnoState — minimal UnoState shim (mirrors test-mine-uno-cpp.cpp)
// ---------------------------------------------------------------------------

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
// Port of `MineUnoWitness::deterministic_valid(epoch, seed)` from Rust.
// Byte-identical to uno/plonky3-ffi/src/mine_uno_witness.rs::deterministic_valid.
// ---------------------------------------------------------------------------

static std::array<uint8_t, 32> rust_expand(uint64_t seed, uint64_t salt) {
    std::array<uint8_t, 32> out{};
    uint64_t x = seed * 0x9E37'79B9'7F4A'7C15ULL;
    x ^= salt;
    for (size_t chunk = 0; chunk < 4; ++chunk) {
        x ^= x << 13;
        x ^= x >>  7;
        x ^= x << 17;
        for (size_t i = 0; i < 8; ++i) {
            out[chunk * 8 + i] = static_cast<uint8_t>((x >> (i * 8)) & 0xFF);
        }
    }
    return out;
}

static std::vector<uint8_t> build_witness_bytes(uint32_t epoch, uint64_t seed) {
    std::vector<uint8_t> out(192, 0);
    for (size_t i = 0; i < 4; ++i) out[i] = (epoch >> (i * 8)) & 0xFF;
    auto d_raw     = rust_expand(seed, 0xD11D11ULL);
    auto nonce_raw = rust_expand(seed, 0xA110CE00ULL);
    auto pk_d_raw  = rust_expand(seed, 0xAFAFAFULL);
    auto ivk_raw   = rust_expand(seed, 0x1CE1CEULL);
    auto rseed_raw = rust_expand(seed, 0x5EED5EEDULL);
    for (size_t i = 11; i < 32; ++i) d_raw[i] = 0;
    std::memcpy(&out[4],   nonce_raw.data(), 32);
    std::memcpy(&out[36],  d_raw.data(),     32);
    std::memcpy(&out[68],  pk_d_raw.data(),  32);
    std::memcpy(&out[100], ivk_raw.data(),   32);
    const uint64_t value_nano     = 50ULL * 1'000'000'000ULL;
    const uint64_t remaining_pre  = 21'000'000ULL * 1'000'000'000ULL;
    const uint64_t remaining_post = remaining_pre - value_nano;
    auto put_u64 = [&](size_t off, uint64_t v) {
        for (size_t i = 0; i < 8; ++i) out[off + i] = (v >> (i * 8)) & 0xFF;
    };
    put_u64(132, value_nano);
    std::memcpy(&out[140], rseed_raw.data(), 32);
    put_u64(172, remaining_pre);
    put_u64(180, remaining_post);
    return out;
}

// ---------------------------------------------------------------------------
// PI byte helpers — pull fields out of the 96 B Plonky3 PI blob.
// Layout: 12 × u64 LE; indices from uno/plonky3-ffi/src/mine_uno_columns.rs.
// ---------------------------------------------------------------------------

static uint64_t pi_u64(const uint8_t* pi, size_t fe_index) {
    uint64_t v = 0;
    for (size_t i = 0; i < 8; ++i) v |= static_cast<uint64_t>(pi[fe_index * 8 + i]) << (i * 8);
    return v;
}

static std::array<uint8_t, 32> pi_output_cm(const uint8_t* pi) {
    // PI[2..6] = output_cm (4 × u64 LE = 32 raw bytes in sequence).
    std::array<uint8_t, 32> out{};
    std::memcpy(out.data(), pi + 16, 32);   // 2 × 8 offset = 16
    return out;
}

static std::array<uint8_t, 32> pi_pow_hash(const uint8_t* pi) {
    // PI[6..10] = pow_hash (4 × u64 LE = 32 raw bytes in sequence).
    std::array<uint8_t, 32> out{};
    std::memcpy(out.data(), pi + 48, 32);   // 6 × 8 offset = 48
    return out;
}

static std::array<uint8_t, 32> strict_target_above(
    const std::array<uint8_t, 32>& hash) {
    auto target = hash;
    for (size_t i = target.size(); i-- > 0;) {
        if (target[i] != 0xff) {
            ++target[i];
            return target;
        }
        target[i] = 0;
    }
    target.fill(0xff);
    return target;
}

// ---------------------------------------------------------------------------
// Result-reporting harness (non-zero exit on any fail).
// ---------------------------------------------------------------------------

static int g_failures = 0;

// Rename to avoid colliding with td/utils/check.h's `CHECK` macro.
#define EXPECT(cond, msg)                                                    \
    do {                                                                     \
        if (!(cond)) {                                                       \
            std::fprintf(stderr, "  FAILED: %s  (%s:%d)\n", (msg),           \
                         __FILE__, __LINE__);                                \
            ++g_failures;                                                    \
        }                                                                    \
    } while (0)

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("MineUno end-to-end apply integration test\n");
    std::printf("==========================================\n\n");

    // Step 1+2: build witness, prove.
    std::printf("[1/6] Building deterministic witness + invoking STARK prover "
                "(~15-25 s)...\n");
    auto witness_bytes = build_witness_bytes(/*epoch=*/0, /*seed=*/0xC0FF'EEULL);
    EXPECT(witness_bytes.size() == 192, "witness should encode to 192 B");

    Plonky3OwnedProof owned{};
    int32_t rc = uno_mine_uno_prove(
        ::Plonky3Witness{witness_bytes.data(), witness_bytes.size()}, &owned);
    EXPECT(rc == 0, "uno_mine_uno_prove must return Ok");
    if (rc != 0) {
        std::fprintf(stderr, "  (rc = %d; likely FFI link mismatch)\n", rc);
        return 1;
    }
    EXPECT(owned.ptr != nullptr && owned.len > 4, "prover returned an owned buffer");

    // Step 3: split owned → (proof_bytes, pi_bytes).
    const uint8_t* bytes = owned.ptr;
    uint32_t proof_len = (uint32_t)bytes[0]
                       | ((uint32_t)bytes[1] <<  8)
                       | ((uint32_t)bytes[2] << 16)
                       | ((uint32_t)bytes[3] << 24);
    EXPECT(owned.len >= (size_t)4 + proof_len, "owned len must hold proof_len");
    // proof bytes are embedded inside `owned` and handed to verify
    // via `tx.proof_blob` below; we only need pi_bytes to fill PI fields.
    const uint8_t* pi_bytes    = bytes + 4 + proof_len;
    size_t         pi_len      = owned.len - 4 - proof_len;
    EXPECT(pi_len == 96, "PI bytes must be 12 × 8 = 96 B");
    std::printf("      Prover returned proof_len=%u, pi_len=%zu.\n",
                (unsigned)proof_len, pi_len);

    // Step 4: build a C++ MineUno that mirrors the Rust PI exactly.
    std::printf("[2/6] Building MineUno tx + encoding to BoC.\n");
    uw::MineUno tx;
    tx.tx_kind   = uw::kTxKindMineUno;
    tx.version   = uw::kMineUnoVersion;
    tx.scheme_id = uw::kSchemeIdV1;
    tx.chain_id  = 0xDEAD'BEEF;
    tx.public_inputs.epoch          = static_cast<uint32_t>(pi_u64(pi_bytes, 0));
    auto pow_hash = pi_pow_hash(pi_bytes);
    tx.public_inputs.target         = strict_target_above(pow_hash);
    tx.public_inputs.value_nano     = pi_u64(pi_bytes, 1);
    tx.public_inputs.output_cm      = pi_output_cm(pi_bytes);
    tx.public_inputs.remaining_pre  = pi_u64(pi_bytes, 10);
    tx.public_inputs.remaining_post = pi_u64(pi_bytes, 11);

    // The MineUno.proof_blob is the concatenated wire used by
    // `apply_mine_uno` in mine_uno.cpp (split_proof_blob peels it into
    // proof + PI). That is exactly what the prover returns in `owned`.
    tx.proof_blob.assign(bytes, bytes + owned.len);

    // Sanity: pull the PI fields we can cross-check independently.
    EXPECT(tx.public_inputs.epoch == 0, "PI.epoch must be 0");
    EXPECT(tx.public_inputs.value_nano == 50ULL * 1'000'000'000ULL,
          "PI.value_nano must equal era-0 reward (50 UNO)");
    EXPECT(tx.public_inputs.remaining_pre == uw::kMineSupplyNano,
          "PI.remaining_pre must equal kMineSupplyNano");
    EXPECT(tx.public_inputs.remaining_post ==
              (uw::kMineSupplyNano - 50ULL * 1'000'000'000ULL),
          "PI.remaining_post must equal supply - era-0 reward");
    EXPECT(tx.public_inputs.target > pow_hash,
          "synthetic target must be strictly above PI.pow_hash");

    // Encode → decode round trip via BoC (same path a JSON-RPC admission
    // would take).
    auto boc_r = uw::encode_mine_uno_to_boc(
        tx, td::Slice(reinterpret_cast<const char*>(tx.proof_blob.data()),
                      tx.proof_blob.size()));
    EXPECT(boc_r.is_ok(), "encode_mine_uno_to_boc must succeed");
    if (boc_r.is_error()) {
        std::fprintf(stderr, "  encode error: %s\n", boc_r.error().message().c_str());
        uno_plonky3_proof_free(owned);
        return 1;
    }
    auto buf = boc_r.move_as_ok();
    std::printf("      BoC encoded: %zu bytes.\n", buf.size());

    std::printf("[3/6] Decoding BoC back into MineUno.\n");
    auto decoded = uw::decode_mine_uno_bytes(buf.as_slice());
    EXPECT(std::holds_alternative<uw::MineUno>(decoded),
          "decode_mine_uno_bytes must succeed on our own BoC");
    if (auto* err = std::get_if<uw::MineUnoDecodeError>(&decoded)) {
        std::fprintf(stderr, "  decode error: %s\n", err->reason.c_str());
        uno_plonky3_proof_free(owned);
        return 1;
    }
    uw::MineUno& dtx = std::get<uw::MineUno>(decoded);
    EXPECT(dtx.public_inputs.value_nano == tx.public_inputs.value_nano,
          "decoded value_nano matches");
    EXPECT(dtx.proof_blob.size() == tx.proof_blob.size(),
          "decoded proof_blob size matches");

    // Step 4a: prove the cheap PoW gate rejects equality. This returns before
    // the expensive STARK verify, so it pins the boundary without a second
    // prover/verifier round.
    {
        std::printf("[4a/6] Asserting pow_hash == target is rejected.\n");
        auto bad_tx = dtx;
        bad_tx.public_inputs.target = pow_hash;
        FakeMineUnoState bad_state;
        bad_state.target_ = pow_hash;
        auto bad_result = uw::apply_mine_uno(bad_state, bad_tx, /*gen_utime=*/0);
        EXPECT(bad_result == uw::VerifyResult::PowHashAboveTarget,
              "target equal to pow_hash must be rejected");
        if (bad_result != uw::VerifyResult::PowHashAboveTarget) {
            std::fprintf(stderr, "  equality result = %s\n",
                         uw::verify_result_name(bad_result));
            uno_plonky3_proof_free(owned);
            return 1;
        }
    }

    // Step 5: apply against the fake state and assert mutations.
    std::printf("[4/6] Applying MineUno to FakeUnoState (real STARK verify)...\n");
    FakeMineUnoState state;
    state.target_ = dtx.public_inputs.target;
    const uint32_t before_epoch = state.epoch_;
    const uint64_t before_rem   = state.remaining_;
    const size_t   before_cms   = state.commitments_.size();
    const size_t   before_tags  = state.filter_tags_.size();

    auto result = uw::apply_mine_uno(state, dtx, /*gen_utime=*/0);
    EXPECT(result == uw::VerifyResult::Ok, "apply_mine_uno must return Ok");
    if (result != uw::VerifyResult::Ok) {
        std::fprintf(stderr, "  result = %s\n", uw::verify_result_name(result));
        uno_plonky3_proof_free(owned);
        return 1;
    }

    std::printf("[5/6] Asserting state mutations.\n");
    EXPECT(state.epoch_ == before_epoch + 1, "epoch must advance by 1");
    EXPECT(state.remaining_ == before_rem - 50ULL * 1'000'000'000ULL,
          "remaining must decrease by 50 UNO");
    EXPECT(state.commitments_.size() == before_cms + 1,
          "commitments must grow by 1");
    EXPECT(state.filter_tags_.size() == before_tags + 1,
          "filter tag must be accumulated");
    if (state.commitments_.size() > before_cms) {
        td::Bits256 cm_expected;
        std::memcpy(cm_expected.as_array().data(),
                    dtx.public_inputs.output_cm.data(), 32);
        EXPECT(state.commitments_.back() == cm_expected,
              "appended commitment must equal PI.output_cm");
    }

    // Step 6: resubmit the same tx — must fail with EpochRaceDetected
    // (state.mine_epoch() is now 1, pi.epoch is still 0).
    std::printf("[6/6] Resubmitting same tx — asserting EpochRaceDetected.\n");
    auto replay_result = uw::apply_mine_uno(state, dtx, /*gen_utime=*/0);
    EXPECT(replay_result == uw::VerifyResult::EpochRaceDetected,
          "resubmitted tx must be rejected with EpochRaceDetected");
    // State must NOT mutate further.
    EXPECT(state.epoch_ == before_epoch + 1,
          "epoch must remain == 1 after race reject");
    EXPECT(state.remaining_ == before_rem - 50ULL * 1'000'000'000ULL,
          "remaining must remain unchanged after race reject");

    uno_plonky3_proof_free(owned);

    std::printf("\n");
    if (g_failures == 0) {
        std::printf("PASS — MineUno end-to-end apply pipeline green.\n");
        return 0;
    }
    std::fprintf(stderr, "FAIL — %d check(s) failed.\n", g_failures);
    return 1;
}
