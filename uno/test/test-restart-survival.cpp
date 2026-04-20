/*
    Uno Workchain — §12 P.4 restart-survival test.

    Per §12 P.4 of doc/uno-workchain.md, a validator that restarts from a
    serialised UnoShardState MUST replay to byte-identical state: the
    commitment-tree root, nullifier set, anchor window, and stats must all
    match pre-crash. This is the core consensus property the chain relies
    on when validators crash-recover.

    Test strategy (K-restart-survival-drive):
      1. Construct a fresh UnoShardState via the adapter.
      2. Pre-seed the anchor window with a deterministic "genesis" anchor
         used by the valid-Transfer fixture so §4.3 step 1.5 passes.
      3. Build 20 valid Transfers via the shared fixture
         (uno/test/fixtures/valid_transfer_fixture.{h,cpp}) and 5
         deliberately-invalid variants covering the canonical reject paths
         (stale anchor, duplicate nullifier pre-spent, bad sig, bad
         chain_id, duplicate-commitment-within-tx). Each invalid variant
         reuses corruption patterns from test-mandatory-negatives.cpp.
      4. Drive every tx through `verify_transfer_serial`:
           - Valid txs reach §4.3 step 4 and reject with BadPlonky3Proof
             (the Plonky3 stub always fails; linking the real verifier
             would flip this to Ok — both outcomes are fine for the
             round-trip invariant). We then call `apply_transfer`
             manually, mirroring the compute-phase's post-step-4 apply.
           - Invalid txs MUST reject earlier, at the specific step each
             corruption targets. We assert the exact VerifyResult.
      5. Record the post-apply StateFingerprint
         (commitment_tree_root, next_position, nullifier_count, anchor
         window digest, stats triplet) and the root-cell hash of
         `serialize_state(state)`.
      6. Construct a fresh adapter handle, call `deserialize_state` on
         the serialised cell tree, re-compute the fingerprint and
         re-serialise. Assert byte-identical match on every field +
         on the root-cell hash.

    Pre-conditions lifted by this change:
      - Shared valid-Transfer fixture (K-p7-fixtures) is landed.
      - `uno/core/cell-state.h` exports serialize_state / deserialize_state.
      - `uno/core/compute-phase.h` exports verify_transfer + apply_transfer
        (and parallel-verify.h exposes `verify_transfer_serial`).

    Previously this test exited with passed=0 / skips=1 because the full
    apply → serialize → deserialize chain was not wired end-to-end; the
    skip is lifted here.
*/

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <random>
#include <string>
#include <unordered_set>
#include <vector>

#include "td/utils/Slice.h"
#include "td/utils/UInt.h"
#include "vm/cells/CellBuilder.h"

// NOTE: state.h / cell-state.h are NOT included here — they would collide
// with compute-phase.h's `UnoState` symbol. The UnoShardState round-trip
// lives behind the opaque adapter in `restart_survival_adapter.{h,cpp}`.
#include "uno/core/compute-phase.h"
#include "uno/core/parallel-verify.h"     // verify_transfer_serial
#include "uno/core/transaction.h"

#include "uno/test/fixtures/valid_transfer_fixture.h"
#include "uno/test/restart_survival_adapter.h"

// ----- Plonky3 / Poseidon2 FFI weak stubs -----------------------------------
// Mirror the pattern in test-uno-end-to-end.cpp / test-uno-mandatory-negatives.cpp
// so this binary links without the real Rust crate. Step 4 of §4.3 rejects
// with BadPlonky3Proof for every valid-up-to-step-3 tx; that's expected and
// absorbed by the driver below.
extern "C" {

struct Plonky3VerifierHandle;
typedef struct { const uint8_t* ptr; std::uintptr_t len; } Plonky3ProofBytes;
typedef struct { const uint8_t* ptr; std::uintptr_t len; } Plonky3PublicInputs;

static std::atomic<int> g_fake_plonky3_handle{0};

__attribute__((weak)) uint32_t uno_plonky3_abi_version(void) { return 1; }

__attribute__((weak)) int32_t uno_plonky3_verifier_init(
    Plonky3VerifierHandle** out) {
    g_fake_plonky3_handle.fetch_add(1, std::memory_order_relaxed);
    *out = reinterpret_cast<Plonky3VerifierHandle*>(&g_fake_plonky3_handle);
    return 0;
}
__attribute__((weak)) void uno_plonky3_verifier_free(
    Plonky3VerifierHandle* /*h*/) {}
__attribute__((weak)) int32_t uno_plonky3_verify(
    const Plonky3VerifierHandle* /*h*/,
    Plonky3ProofBytes /*proof*/, Plonky3PublicInputs /*pi*/) {
    return 4;  // Plonky3Status::VerifyFailed — unreachable branches never hit
}

__attribute__((weak)) void uno_poseidon2_goldilocks_permute_t8(uint64_t s[8]) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (int i = 0; i < 8; ++i) { h ^= s[i]; h *= 0x100000001b3ULL; }
    for (int i = 0; i < 8; ++i) {
        h = (h * 0x100000001b3ULL) ^ (s[i] + static_cast<uint64_t>(i) * 0x9E3779B97F4A7C15ULL);
        s[i] = h % 0xFFFFFFFF00000001ULL;
    }
}
__attribute__((weak)) void uno_poseidon2_goldilocks_permute_t16(uint64_t s[16]) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (int i = 0; i < 16; ++i) { h ^= s[i]; h *= 0x100000001b3ULL; }
    for (int i = 0; i < 16; ++i) {
        h = (h * 0x100000001b3ULL) ^ (s[i] + static_cast<uint64_t>(i) * 0x9E3779B97F4A7C15ULL);
        s[i] = h % 0xFFFFFFFF00000001ULL;
    }
}

}  // extern "C"

// ----- Tracked-printf harness -----------------------------------------------

static std::atomic<int> g_failures{0};
static std::atomic<int> g_skips{0};
static std::atomic<int> g_passes{0};

static int tracked_printf(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    va_list copy;
    va_copy(copy, args);
    int needed = std::vsnprintf(nullptr, 0, fmt, copy);
    va_end(copy);
    std::string rendered;
    if (needed >= 0) {
        rendered.resize((size_t)needed + 1);
        va_copy(copy, args);
        std::vsnprintf(rendered.data(), rendered.size(), fmt, copy);
        va_end(copy);
        rendered.resize((size_t)needed);
    }
    int written = std::vprintf(fmt, args);
    va_end(args);
    if (!rendered.empty()) {
        if (rendered.find("FAILED") != std::string::npos) g_failures.fetch_add(1);
        if (rendered.find("SKIP")    != std::string::npos) g_skips.fetch_add(1);
        if (rendered.find("PASSED")  != std::string::npos) g_passes.fetch_add(1);
    }
    return written;
}
#define tprintf tracked_printf

// ---------------------------------------------------------------------------
// ShardStateAdapter — subclass of the abstract UnoState (compute-phase.h)
// that forwards every virtual through the opaque StateHandle adapter.
//
// ## ODR-violation workaround (padding buffer)
//
// The Uno Workchain has two classes named `uno_workchain::UnoState`
// compiled into the same archive: the abstract base in
// `uno/core/compute-phase.h` (8 B, pure-virtual, no state fields) and
// the concrete RPC facade in `uno/core/state.h` (≈320 B: holds a
// UnoShardState + a BlockFilterBuilder pointer + a shared_mutex).
// They share the same mangled symbol for the default constructor and
// destructor. Because `restart_survival_adapter.cpp` pulls
// `state.cpp` (via `UnoShardState::make_empty`), the linker resolves
// every call to `UnoState::UnoState()` / `~UnoState()` against the
// state.cpp strong symbol. That body zero-memsets ~320 B starting at
// `this` — way more than the 16 B the compiler allocated for a
// ShardStateAdapter whose only visible base is the 8-B abstract class,
// so the spurious write clobbers surrounding stack.
//
// We pad the subclass with a sacrificial buffer sized to ABSORB the
// concrete UnoState's memset. The compiler still lays the vptr slot
// + padding out as a single object; every virtual call on
// `ShardStateAdapter*` dispatches through the subclass's own vtable
// (the compiler builds that vtable from the in-TU view of the
// abstract class); the padding only keeps the spurious 320-byte
// memset from spilling onto the caller's locals.
//
// The proper fix belongs in `uno/core/` (rename one of the `UnoState`
// classes, or have them share a single abstract base). The task
// contract forbids modifying `uno/core/` from this test, so this
// padding keeps the restart-survival invariant checkable here-and-now.
// ---------------------------------------------------------------------------
namespace {

namespace tr = uno_workchain::test_restart;

// Deterministic driver-side config. Matches test-mandatory-negatives.cpp's
// FakeUnoState so valid-Transfer-fixture txs built against it pass §4.3
// step 1.
constexpr uint32_t kDriverChainId             = 0xC0FFEE;
constexpr uint64_t kDriverCurrentBlockSeqno   = 100;
constexpr uint32_t kDriverExpiryWindowBlocks  = 256;

class ShardStateAdapter : public uno_workchain::UnoState {
public:
    // ODR-workaround sacrificial padding (see class docstring). Sized
    // to absorb the concrete state.cpp `UnoState::UnoState()` body's
    // field initialisers (≈320 B for `state_(UnoShardState)` +
    // `current_block_filter_` unique_ptr + `mutex_` shared_mutex).
    // Placed AS THE FIRST MEMBER so the spurious writes land here and
    // NOT on `handle_`. The pad occupies offsets 8..8+1024 in the
    // subclass layout; state.cpp's `state_` member sits at offset 8
    // of state.h's UnoState, so the overlap is complete. Our own
    // subclass ctor sets the vptr / `handle_` AFTER the base ctor
    // returns, which restores the slot to the correct vtable + value.
    alignas(void*) unsigned char _odr_pad[1024]{};

    ShardStateAdapter() : handle_(tr::adapter_make_empty()) {
        // Re-zero the pad (the base ctor may have left it in an
        // unspecified state). Not strictly required — we never read
        // _odr_pad — but makes reruns reproducible under ASan.
        std::memset(_odr_pad, 0, sizeof(_odr_pad));
    }
    ~ShardStateAdapter() override { tr::adapter_destroy(handle_); }

    ShardStateAdapter(const ShardStateAdapter&)            = delete;
    ShardStateAdapter& operator=(const ShardStateAdapter&) = delete;

    tr::StateHandle*       handle() noexcept       { return handle_; }
    const tr::StateHandle* handle() const noexcept { return handle_; }

    // ---- Config ----
    uint32_t expected_chain_id() const override    { return kDriverChainId; }
    uint64_t current_block_seqno() const override  { return kDriverCurrentBlockSeqno; }
    uint32_t expiry_window_blocks() const override { return kDriverExpiryWindowBlocks; }
    uint64_t min_fee_nano() const override         { return 0; }
    uint64_t fee_per_byte_nano() const override    { return 0; }
    uint64_t fee_per_spend_nano() const override   { return 0; }
    uint64_t fee_per_output_nano() const override  { return 0; }

    // ---- Verify-phase reads ----
    bool anchor_window_contains(const td::Bits256& a) const override {
        return tr::adapter_anchor_window_contains(
            handle_, reinterpret_cast<const uint8_t*>(a.data()));
    }
    bool nullifier_is_spent(const td::Bits256& nf) const override {
        return tr::adapter_nullifier_is_spent(
            handle_, reinterpret_cast<const uint8_t*>(nf.data()));
    }

    // ---- Apply-phase mutations ----
    void append_commitment(const td::Bits256& cm) override {
        tr::adapter_append_commitment(
            handle_, reinterpret_cast<const uint8_t*>(cm.data()));
    }
    void insert_nullifier(const td::Bits256& nf) override {
        tr::adapter_insert_nullifier(
            handle_, reinterpret_cast<const uint8_t*>(nf.data()));
    }
    void accumulate_filter_tag(uint16_t /*t*/) override {
        // Not part of the serialised state root in v1 (§5.1: the block
        // filter is rotated out at end-of-block into a separate indexed
        // store, not into UnoShardState). Safe to discard here.
    }
    void bump_stats(uint64_t fee, uint64_t note_count_delta) override {
        tr::adapter_bump_stats(handle_, fee, note_count_delta);
    }

    td::Ref<vm::Cell> serialize_to_cell() const override {
        return tr::adapter_serialize(handle_);
    }

private:
    tr::StateHandle* handle_{nullptr};
};

// Pinned genesis anchor — a stable 32-byte value used by every tx in the
// batch so §4.3 step 1.5 (`anchor_window_contains`) passes. Matches the
// pattern in test-uno-mandatory-negatives.cpp's `build_valid_tx_for_state`.
td::Bits256 make_genesis_anchor() {
    td::Bits256 a{};
    for (int i = 0; i < 32; ++i) {
        a.data()[i] = static_cast<uint8_t>(0x5A ^ (i * 7));
    }
    return a;
}

// Unique spend-nullifier / rcm seed per tx, so no two valid fixture
// Transfers end up with colliding nullifiers or commitments.
std::array<uint8_t, 32> tx_nullifier(uint64_t idx) {
    std::array<uint8_t, 32> nf{};
    for (int i = 0; i < 32; ++i) {
        nf[i] = static_cast<uint8_t>((idx * 131 + i * 17) & 0xff);
    }
    // Stamp the index into the trailing bytes so the first-byte of the
    // nullifier (high-entropy) is driven by idx alone.
    for (int i = 0; i < 8; ++i) {
        nf[24 + i] = static_cast<uint8_t>((idx >> (8 * i)) & 0xff);
    }
    return nf;
}

// Build a valid-up-to-§4.3-step-3 Transfer with unique nullifier for tx `idx`.
// Signed via the fixture's Schnorr path.
uno_workchain::test_fixtures::ValidTransferFixture
build_valid_tx(const uno_workchain::test_fixtures::DemoWallet& sender,
               const uno_workchain::test_fixtures::DemoWallet& receiver,
               const td::Bits256&                              anchor,
               uint64_t                                        idx) {
    uno_workchain::test_fixtures::ValidTransferParams params;
    params.sender       = &sender;
    params.receiver     = &receiver;
    params.spend_value  = 100'000'000'000ULL;                          // 100 UNO
    params.fee_nano     = 255'000ULL + idx;                             // unique per tx
    params.anchor       = anchor;
    params.expiry_block = kDriverCurrentBlockSeqno + 16;
    params.chain_id     = kDriverChainId;
    // Two outputs with a balanced split, fee absorbed against the spend.
    uint64_t to_recv = 40'000'000'000ULL + idx * 1'000ULL;
    uint64_t change  = params.spend_value - to_recv - params.fee_nano;
    params.outputs.resize(2);
    params.outputs[0].value = to_recv;
    params.outputs[1].value = change;
    // Override the nullifier so every valid tx has a unique spend.
    params.override_nullifier = true;
    params.nullifier_bytes    = tx_nullifier(idx);
    return uno_workchain::test_fixtures::make_valid_transfer(params);
}

// Serialise a td::Ref<vm::Cell>'s root-hash to 32 bytes. Null cell → zeros.
std::array<uint8_t, 32> root_hash_of(const td::Ref<vm::Cell>& c) {
    std::array<uint8_t, 32> out{};
    if (c.is_null()) return out;
    td::Bits256 h(c->get_hash().bits());
    std::memcpy(out.data(), h.data(), 32);
    return out;
}

bool fingerprints_equal(const tr::StateFingerprint& a,
                        const tr::StateFingerprint& b) {
    return a.commitment_tree_root == b.commitment_tree_root
        && a.next_position        == b.next_position
        && a.nullifier_set_root   == b.nullifier_set_root
        && a.anchor_window_size   == b.anchor_window_size
        && a.anchor_window_digest == b.anchor_window_digest
        && a.stats_burned_fees    == b.stats_burned_fees
        && a.stats_tx_count       == b.stats_tx_count
        && a.stats_note_count     == b.stats_note_count;
}

void hex32(const std::array<uint8_t, 32>& a, char out[65]) {
    static const char* H = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        out[2 * i]     = H[(a[i] >> 4) & 0xf];
        out[2 * i + 1] = H[a[i] & 0xf];
    }
    out[64] = '\0';
}

}  // anonymous namespace

// ---------------------------------------------------------------------------
// Test 1: apply → serialize → deserialize → re-serialize byte-identical
// ---------------------------------------------------------------------------
static void test_restart_survival_round_trip() {
    tprintf("[TEST] test_restart_survival_round_trip "
            "(20 valid + 5 invalid → serialise → deserialise → compare)\n");

    ShardStateAdapter state;

    // Seed the anchor window with a genesis anchor AND with the empty-tree
    // root (pushed by `adapter_make_empty` already). The genesis anchor is
    // what every valid-Transfer-fixture tx references.
    auto genesis_anchor = make_genesis_anchor();
    tr::adapter_push_anchor_bytes(
        state.handle(),
        reinterpret_cast<const uint8_t*>(genesis_anchor.data()));

    // --- Build wallets (deterministic) --------------------------------------
    auto alice = uno_workchain::test_fixtures::make_wallet("Alice", 0xA1);
    auto bob   = uno_workchain::test_fixtures::make_wallet("Bob",   0xB0);

    // --- Build the 20 valid + 5 invalid tx batch ----------------------------
    struct BatchEntry {
        uno_workchain::Transfer                 tx;
        uno_workchain::VerifyResult             expected{uno_workchain::VerifyResult::Ok};
        bool                                    apply_after{false};   // apply-manually when verify's step-4-stub masks the accept
        const char*                             label{""};
    };
    std::vector<BatchEntry> batch;

    // Owning buffer for the Schnorr material of each fixture — the spend
    // signatures are already written into each `tx`, so we just need the
    // fixtures to stay alive through verify (signed objects live in `tx`,
    // not rsk). Kept as a vector to extend the lifetime scope.
    std::vector<uno_workchain::test_fixtures::ValidTransferFixture> valid_fx;
    valid_fx.reserve(25);

    constexpr int kValidCount   = 20;
    constexpr int kInvalidCount = 5;

    // 20 valid txs. Each reaches step 4 and rejects with BadPlonky3Proof
    // under the weak stub; we manually apply each one after verify.
    for (int i = 0; i < kValidCount; ++i) {
        auto fx = build_valid_tx(alice, bob, genesis_anchor, /*idx=*/(uint64_t)i);
        BatchEntry be;
        be.tx          = fx.tx;
        be.expected    = uno_workchain::VerifyResult::BadPlonky3Proof;
        be.apply_after = true;
        be.label       = "valid";
        valid_fx.push_back(std::move(fx));
        batch.push_back(std::move(be));
    }

    // Invalid #1: stale anchor (not in window). Should reject at §4.3 step 1.5.
    {
        auto fx = build_valid_tx(alice, bob, genesis_anchor,
                                  /*idx=*/(uint64_t)(kValidCount + 1000));
        // Corrupt the anchor AFTER the fixture built the signed tx; step
        // 1.5 rejects before §4.3 step 3 (Schnorr), so the stale sig is
        // irrelevant here.
        for (int i = 0; i < 32; ++i) {
            fx.tx.anchor.data()[i] = static_cast<uint8_t>(0xE0 ^ i);
        }
        BatchEntry be;
        be.tx       = fx.tx;
        be.expected = uno_workchain::VerifyResult::UnknownAnchor;
        be.label    = "stale-anchor";
        valid_fx.push_back(std::move(fx));
        batch.push_back(std::move(be));
    }

    // Invalid #2: duplicate nullifier (pre-spent). Should reject at
    // §4.3 step 2.
    {
        auto fx = build_valid_tx(alice, bob, genesis_anchor,
                                  /*idx=*/(uint64_t)(kValidCount + 2000));
        // Reuse the nullifier of valid tx #0 so state lookup returns true.
        std::memcpy(fx.tx.spends[0].nullifier.data(),
                    tx_nullifier(0).data(), 32);
        // Re-sign so steps 1–1.7 still pass (tx_hash depends on nullifier
        // bytes, so the fixture's original sig would fail at step 3 and
        // mask the step-2 reject).
        uno_workchain::test_fixtures::resign_spend0(fx);
        BatchEntry be;
        be.tx       = fx.tx;
        be.expected = uno_workchain::VerifyResult::NullifierAlreadySpent;
        be.label    = "replay-nullifier";
        valid_fx.push_back(std::move(fx));
        batch.push_back(std::move(be));
    }

    // Invalid #3: corrupted Schnorr signature. Should reject at §4.3 step 3.
    {
        auto fx = build_valid_tx(alice, bob, genesis_anchor,
                                  /*idx=*/(uint64_t)(kValidCount + 3000));
        // Flip a byte inside the 64-byte sig. No re-sign.
        fx.tx.spends[0].spend_auth_sig[7] ^= 0xff;
        BatchEntry be;
        be.tx       = fx.tx;
        be.expected = uno_workchain::VerifyResult::BadSpendAuthSig;
        be.label    = "bad-sig";
        valid_fx.push_back(std::move(fx));
        batch.push_back(std::move(be));
    }

    // Invalid #4: bad chain_id. Should reject at §4.3 step 1 (BadChainId).
    // Deliberately does NOT pass state's expected_chain_id.
    {
        auto fx = build_valid_tx(alice, bob, genesis_anchor,
                                  /*idx=*/(uint64_t)(kValidCount + 4000));
        fx.tx.chain_id = 0xDEADBEEF;  // != kDriverChainId
        // No need to re-sign; chain_id check is step 1, before Schnorr.
        BatchEntry be;
        be.tx       = fx.tx;
        be.expected = uno_workchain::VerifyResult::BadChainId;
        be.label    = "bad-chain-id";
        valid_fx.push_back(std::move(fx));
        batch.push_back(std::move(be));
    }

    // Invalid #5: duplicate commitment WITHIN one tx. Should reject at
    // §4.3 step 1.6 (DuplicateCommitmentInTx).
    {
        auto fx = build_valid_tx(alice, bob, genesis_anchor,
                                  /*idx=*/(uint64_t)(kValidCount + 5000));
        // Overwrite outputs[1].cm with outputs[0].cm so the intra-tx
        // uniqueness check fires.
        std::memcpy(fx.tx.outputs[1].cm.data(),
                    fx.tx.outputs[0].cm.data(), 32);
        BatchEntry be;
        be.tx       = fx.tx;
        be.expected = uno_workchain::VerifyResult::DuplicateCommitmentInTx;
        be.label    = "dup-cm-in-tx";
        valid_fx.push_back(std::move(fx));
        batch.push_back(std::move(be));
    }

    if ((int)batch.size() != kValidCount + kInvalidCount) {
        tprintf("  FAILED: batch size %zu != expected %d\n",
                batch.size(), kValidCount + kInvalidCount);
        return;
    }

    // --- Drive verify_transfer_serial over the batch ------------------------
    int applied    = 0;
    int early_ok   = 0;    // valid txs whose verify returned Ok (real prover)
    int late_rej   = 0;    // valid txs that rejected at step 4 (stub prover)
    int invalid_ok = 0;    // invalid txs whose verify matched expected reject
    for (size_t i = 0; i < batch.size(); ++i) {
        auto vr = uno_workchain::verify_transfer_serial(state, batch[i].tx);
        if (batch[i].apply_after) {
            // Valid path. Under stubs vr == BadPlonky3Proof; if the real
            // Rust crate is ever linked into this TU, vr could be Ok. Both
            // are acceptable — we apply either way (the valid-up-to-step-3
            // guarantee of the fixture is what matters for the post-state).
            if (vr == uno_workchain::VerifyResult::Ok) {
                ++early_ok;
            } else if (vr == uno_workchain::VerifyResult::BadPlonky3Proof) {
                ++late_rej;
            } else {
                tprintf("  FAILED: valid tx #%zu (label=%s) unexpected "
                        "verify result: %s\n", i, batch[i].label,
                        uno_workchain::verify_result_name(vr));
                return;
            }
            // Mirror the compute-phase post-step-4 apply. `apply_transfer`
            // lives in compute-phase.cpp but is not surfaced through a
            // header — replicate its five-line body inline. See §4.3 step 5.
            for (const auto& o : batch[i].tx.outputs) {
                state.append_commitment(o.cm);
                state.accumulate_filter_tag(o.filter_tag);
            }
            for (const auto& s : batch[i].tx.spends) {
                state.insert_nullifier(s.nullifier);
            }
            state.bump_stats(batch[i].tx.fee, batch[i].tx.outputs.size());
            ++applied;
        } else {
            // Invalid path. Assert the exact reject code.
            if (vr != batch[i].expected) {
                tprintf("  FAILED: invalid tx #%zu (label=%s) expected %s, "
                        "got %s\n", i, batch[i].label,
                        uno_workchain::verify_result_name(batch[i].expected),
                        uno_workchain::verify_result_name(vr));
                return;
            }
            ++invalid_ok;
        }
    }

    if (applied != kValidCount) {
        tprintf("  FAILED: applied=%d, expected %d\n", applied, kValidCount);
        return;
    }
    if (invalid_ok != kInvalidCount) {
        tprintf("  FAILED: invalid_ok=%d, expected %d\n",
                invalid_ok, kInvalidCount);
        return;
    }
    tprintf("  apply: %d valid applied (%d early-ok, %d step-4-rejected), "
            "%d invalid rejected as expected\n",
            applied, early_ok, late_rej, invalid_ok);

    // --- Record pre-restart state -------------------------------------------
    auto pre_fp   = tr::adapter_fingerprint(state.handle());
    auto pre_cell = tr::adapter_serialize(state.handle());
    if (pre_cell.is_null()) {
        tprintf("  FAILED: serialize_state returned null cell\n");
        return;
    }
    auto pre_root_hash = root_hash_of(pre_cell);

    char pre_root_hex[65];
    hex32(pre_root_hash, pre_root_hex);
    tprintf("  pre-restart: root_hash=%.16s..%.16s, "
            "next_position=%llu, stats.tx=%llu, stats.notes=%llu\n",
            pre_root_hex, pre_root_hex + 48,
            (unsigned long long)pre_fp.next_position,
            (unsigned long long)pre_fp.stats_tx_count,
            (unsigned long long)pre_fp.stats_note_count);

    // --- Round-trip through a brand-new handle ------------------------------
    ShardStateAdapter restart;
    if (!tr::adapter_deserialize_into(restart.handle(), pre_cell)) {
        tprintf("  FAILED: deserialize_state returned false on first RT\n");
        return;
    }

    auto post_fp   = tr::adapter_fingerprint(restart.handle());
    auto post_cell = tr::adapter_serialize(restart.handle());
    if (post_cell.is_null()) {
        tprintf("  FAILED: serialize_state (post-restart) returned null\n");
        return;
    }
    auto post_root_hash = root_hash_of(post_cell);

    if (!fingerprints_equal(pre_fp, post_fp)) {
        tprintf("  FAILED: state fingerprint drift across restart "
                "(ctr_root=%s, nf_set_root=%s, np=%llu→%llu, "
                "aw_size=%zu→%zu, stats=%llu/%llu/%llu → %llu/%llu/%llu)\n",
                (pre_fp.commitment_tree_root == post_fp.commitment_tree_root ? "ok" : "DRIFT"),
                (pre_fp.nullifier_set_root == post_fp.nullifier_set_root ? "ok" : "DRIFT"),
                (unsigned long long)pre_fp.next_position,
                (unsigned long long)post_fp.next_position,
                pre_fp.anchor_window_size, post_fp.anchor_window_size,
                (unsigned long long)pre_fp.stats_burned_fees,
                (unsigned long long)pre_fp.stats_tx_count,
                (unsigned long long)pre_fp.stats_note_count,
                (unsigned long long)post_fp.stats_burned_fees,
                (unsigned long long)post_fp.stats_tx_count,
                (unsigned long long)post_fp.stats_note_count);
        return;
    }
    if (pre_root_hash != post_root_hash) {
        char post_root_hex[65];
        hex32(post_root_hash, post_root_hex);
        tprintf("  FAILED: root-cell hash drift across restart\n"
                "           pre=%s\n          post=%s\n",
                pre_root_hex, post_root_hex);
        return;
    }

    // --- Second round-trip (deserialise into a THIRD handle, re-serialise,
    //     re-hash). Pins idempotence: deserialise is a stable projection.
    ShardStateAdapter restart2;
    if (!tr::adapter_deserialize_into(restart2.handle(), post_cell)) {
        tprintf("  FAILED: deserialize_state returned false on second RT\n");
        return;
    }
    auto post2_cell = tr::adapter_serialize(restart2.handle());
    auto post2_root_hash = root_hash_of(post2_cell);
    if (post2_root_hash != pre_root_hash) {
        tprintf("  FAILED: root-cell hash drift on second round-trip\n");
        return;
    }

    tprintf("  PASSED (20 valid + 5 invalid → apply → serialise → "
            "deserialise → re-serialise yields byte-identical root; "
            "second-RT also matches)\n");
}

// ---------------------------------------------------------------------------
// Test 2: empty-state round-trip. A freshly-constructed UnoShardState with
// no applied txs MUST serialise and deserialise to itself byte-for-byte.
// This is the boot-from-genesis path the validator takes on a clean start
// (§10.3); a regression here would brick cold-start.
// ---------------------------------------------------------------------------
static void test_empty_state_round_trip() {
    tprintf("[TEST] test_empty_state_round_trip\n");

    ShardStateAdapter state;
    auto cell = tr::adapter_serialize(state.handle());
    if (cell.is_null()) {
        tprintf("  FAILED: empty-state serialize returned null\n");
        return;
    }
    auto root_hash = root_hash_of(cell);

    ShardStateAdapter restart;
    if (!tr::adapter_deserialize_into(restart.handle(), cell)) {
        tprintf("  FAILED: empty-state deserialize returned false\n");
        return;
    }

    auto pre_fp  = tr::adapter_fingerprint(state.handle());
    auto post_fp = tr::adapter_fingerprint(restart.handle());
    if (!fingerprints_equal(pre_fp, post_fp)) {
        tprintf("  FAILED: empty-state fingerprint drift\n");
        return;
    }

    auto cell2 = tr::adapter_serialize(restart.handle());
    auto root_hash2 = root_hash_of(cell2);
    if (root_hash != root_hash2) {
        tprintf("  FAILED: empty-state root-cell hash drift\n");
        return;
    }
    tprintf("  PASSED (empty UnoShardState round-trips byte-identically)\n");
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    // Make stdout unbuffered so a mid-test abort (shouldn't happen, but
    // guarded against here) doesn't eat the FAILED / PASSED markers that
    // the tracked_printf harness counts on.
    std::setvbuf(stdout, nullptr, _IONBF, 0);

    tprintf("Uno Workchain — §12 P.4 restart-survival\n");
    tprintf("=========================================\n\n");

    test_empty_state_round_trip();
    test_restart_survival_round_trip();

    tprintf("\nTotal: passed=%d, failures=%d, skips=%d\n",
            g_passes.load(), g_failures.load(), g_skips.load());
    return g_failures.load() == 0 ? 0 : 1;
}
