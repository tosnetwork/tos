/*
    Uno Workchain — C++ integration test for the A6-3 BlockProofVerifier
    RAII bridge (K-block-proof-verifier-cpp).

    This test pins the C++-side contract of the `uno::crypto::BlockProofVerifier`
    / `uno::crypto::BlockExtraView` pair against the real Rust `uno_plonky3_ffi`
    staticlib. Scope is deliberately narrow:

      1. Construction / init / is_initialized lifecycle. Default-constructed
         verifier holds a null handle; `init()` flips it to `is_initialized() ==
         true`; a second `init()` on the same instance is a no-op returning true.

      2. `BlockExtraView::decode` round-trip: build a known-valid `UnoBlockExtra`
         wire blob via `uno_block_extra_encode_v1`, feed it through the C++
         decode factory, check the accessors return the encoder inputs verbatim.
         RAII-free of the owned proof buffer is exercised by scope-exit; we
         can't directly observe the free from C++ but any leak would show up
         under valgrind / asan.

      3. `BlockExtraView::decode` reject paths:
           - truncated buffer (< 40 B framing header)         → kProofDecodeFailed
           - bad scheme_id in an otherwise-well-formed header → kProofDecodeFailed
           - `proof_len` declaring an over-cap (> 16 MB) tail → kLengthTooLarge
         Each case must leave the returned view in the empty (not-owned) state.

      4. `BlockProofVerifier::verify` reject paths (without requiring a real
         block proof on disk):
           - garbage proof bytes + plausible PI → kProofDecodeFailed (Rust-
             side postcard decode fails before any constraint check runs).
           - default-constructed / un-init'd verifier → kNullPointer (the C++
             shim's null-handle guard).

      5. Static compile-time soundness claims the Rust side cannot easily
         check:
           - BlockExtraView / BlockProofVerifier are non-copyable.
           - Move transfers ownership and leaves moved-from view empty.
           - Key FFI structs have the sizes the header assumes.

    End-to-end real-proof verify from C++ is intentionally NOT covered here.
    Producing an on-disk block proof from C++ requires Rust-side helpers that
    don't exist at C++ scope, and the Rust crate's own
    `block_verifier_ffi_round_trip` test in lib.rs already exercises the full
    encode → decode → verify pipeline against a prover-generated proof. If a
    pre-generated fixture file ever lands under `uno/test/fixtures/`, this
    file can be extended to read it and assert kOk.

    Build against: uno_workchain (uno/crypto/block-proof-verifier.h plus the
    real uno_plonky3_ffi staticlib via Corrosion). When the Rust staticlib is
    absent (Corrosion not configured), the weak-symbol stubs in
    uno/core/parallel-verify.cpp won't resolve the A6-2/A6-3 FFI entry points
    (`uno_block_*`), so the link will fail — this is intentional: an
    integration test pinning the block-verifier FFI MUST run against the real
    Rust side. Downstream CI can skip this binary if Corrosion is stripped.
*/

#include "uno/crypto/block-proof-verifier.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <type_traits>
#include <utility>
#include <vector>

namespace {

// -- Minimal test harness (mirrors test-nullifier-warm-lru.cpp) --------------

int g_passed = 0;
int g_failed = 0;

#define EXPECT_TRUE(cond, label)                                            \
    do {                                                                    \
        if (cond) {                                                         \
            ++g_passed;                                                     \
        } else {                                                            \
            ++g_failed;                                                     \
            std::fprintf(stderr,                                            \
                         "  FAIL: %s (%s:%d)\n", (label), __FILE__,         \
                         __LINE__);                                         \
        }                                                                   \
    } while (0)

#define EXPECT_FALSE(cond, label) EXPECT_TRUE(!(cond), label)

#define EXPECT_EQ(a, b, label)                                              \
    do {                                                                    \
        auto _a = (a);                                                      \
        auto _b = (b);                                                      \
        if (_a == _b) {                                                     \
            ++g_passed;                                                     \
        } else {                                                            \
            ++g_failed;                                                     \
            std::fprintf(stderr,                                            \
                         "  FAIL: %s (%s:%d): %lld != %lld\n", (label),     \
                         __FILE__, __LINE__,                                \
                         static_cast<long long>(_a),                        \
                         static_cast<long long>(_b));                       \
        }                                                                   \
    } while (0)

// Compile-time soundness claims --------------------------------------------

using uno::crypto::BlockExtraView;
using uno::crypto::BlockProofVerifier;
using uno::crypto::VerifyResult;

static_assert(!std::is_copy_constructible_v<BlockExtraView>,
              "BlockExtraView must be non-copyable");
static_assert(!std::is_copy_assignable_v<BlockExtraView>,
              "BlockExtraView must be non-copy-assignable");
static_assert(std::is_nothrow_move_constructible_v<BlockExtraView>,
              "BlockExtraView move-construct must be noexcept");
static_assert(std::is_nothrow_move_assignable_v<BlockExtraView>,
              "BlockExtraView move-assign must be noexcept");
static_assert(std::is_nothrow_default_constructible_v<BlockExtraView>,
              "BlockExtraView default-construct must be noexcept");

static_assert(!std::is_copy_constructible_v<BlockProofVerifier>,
              "BlockProofVerifier must be non-copyable");
static_assert(!std::is_copy_assignable_v<BlockProofVerifier>,
              "BlockProofVerifier must be non-copy-assignable");
static_assert(std::is_nothrow_move_constructible_v<BlockProofVerifier>,
              "BlockProofVerifier move-construct must be noexcept");
static_assert(std::is_nothrow_move_assignable_v<BlockProofVerifier>,
              "BlockProofVerifier move-assign must be noexcept");

// Layout sanity checks — if cbindgen drifts these, the whole bridge breaks
// silently. Cheap guard.
static_assert(sizeof(UnoBlockExtraBytes) == sizeof(void*) + sizeof(std::size_t),
              "UnoBlockExtraBytes layout drift");
static_assert(sizeof(UnoBlockPublicInputsView) >= 32 + 8 * 3,
              "UnoBlockPublicInputsView too small for its declared fields");

// -- Helpers -----------------------------------------------------------------

// Build a canonical v1 UnoBlockExtra wire blob holding `proof_bytes` as the
// aggregated payload. Returns the allocation directly through the
// Plonky3OwnedProof struct — caller must free via `uno_plonky3_proof_free`
// exactly once.
Plonky3OwnedProof encode_v1(std::uint16_t n_transfers,
                            const std::uint8_t (&tx_pi_merkle_root)[32],
                            const std::uint8_t* proof_bytes,
                            std::size_t proof_len) {
    Plonky3OwnedProof out{};
    const std::int32_t rc = uno_block_extra_encode_v1(
        n_transfers,
        tx_pi_merkle_root,
        proof_bytes,
        static_cast<std::uintptr_t>(proof_len),
        &out);
    if (rc != 0) {
        std::fprintf(stderr,
                     "  encode_v1 returned status=%d (expected 0)\n", rc);
        out = Plonky3OwnedProof{};
    }
    return out;
}

// Little-endian u16 write.
void write_le_u16(std::uint8_t* p, std::uint16_t v) {
    p[0] = static_cast<std::uint8_t>(v & 0xFF);
    p[1] = static_cast<std::uint8_t>((v >> 8) & 0xFF);
}

// Little-endian u32 write.
void write_le_u32(std::uint8_t* p, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) {
        p[i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF);
    }
}

// -- Case 1 ------------------------------------------------------------------
// Construction / init / is_initialized / double-init lifecycle.

void case_verifier_lifecycle() {
    std::fprintf(stderr, "case: BlockProofVerifier construction + init lifecycle\n");

    // Default-constructed: no handle.
    BlockProofVerifier v;
    EXPECT_FALSE(v.is_initialized(), "default-constructed verifier has no handle");

    // init() flips the handle to non-null.
    const bool ok1 = v.init();
    EXPECT_TRUE(ok1, "init() succeeds on a fresh instance");
    EXPECT_TRUE(v.is_initialized(), "is_initialized() true after init()");

    // Second init() is a no-op that still returns true.
    const bool ok2 = v.init();
    EXPECT_TRUE(ok2, "double-init() returns true (no-op)");
    EXPECT_TRUE(v.is_initialized(), "still initialized after double-init()");

    // Destructor runs at scope exit; we can't observe the handle free from
    // C++ but any double-free would panic / assert in the Rust `Box::from_raw`
    // path. Sanitiser builds catch it.
}

// -- Case 2 ------------------------------------------------------------------
// BlockExtraView::decode round-trip against a known-valid v1 wire blob.

void case_decode_round_trip() {
    std::fprintf(stderr, "case: BlockExtraView::decode round-trips a v1 blob\n");

    std::uint8_t root[32];
    for (int i = 0; i < 32; ++i) root[i] = static_cast<std::uint8_t>(0xAA ^ i);

    // A non-trivial proof payload with a distinct byte pattern — we will
    // check that the decoded view exposes the identical bytes.
    std::vector<std::uint8_t> proof(256);
    for (std::size_t i = 0; i < proof.size(); ++i) {
        proof[i] = static_cast<std::uint8_t>((i * 31) & 0xFF);
    }

    const std::uint16_t n_transfers = 7;
    Plonky3OwnedProof wire = encode_v1(n_transfers, root, proof.data(), proof.size());
    EXPECT_TRUE(wire.ptr != nullptr, "encode_v1 produced a non-null wire buffer");
    EXPECT_TRUE(wire.len >= 40 + proof.size(),
                "wire buffer is at least header + proof bytes");

    {
        auto result = BlockExtraView::decode(wire.ptr, static_cast<std::size_t>(wire.len));
        EXPECT_TRUE(result.has_value(), "decode() succeeds on a canonical blob");
        EXPECT_EQ(static_cast<long long>(result.status),
                  static_cast<long long>(VerifyResult::kOk),
                  "decode() status is kOk");

        const auto& view = result.view;
        EXPECT_TRUE(view.has_payload(), "view has owned payload on Ok decode");
        EXPECT_EQ(static_cast<long long>(view.scheme_id()),
                  static_cast<long long>(UNO_AGGREGATOR_SCHEME_ID_V1),
                  "scheme_id round-trips");
        EXPECT_EQ(static_cast<long long>(view.version()),
                  static_cast<long long>(UNO_AGGREGATOR_VERSION_V1),
                  "version round-trips");
        EXPECT_EQ(static_cast<long long>(view.n_transfers()),
                  static_cast<long long>(n_transfers),
                  "n_transfers round-trips");

        const std::uint8_t* got_root = view.tx_pi_merkle_root();
        EXPECT_TRUE(got_root != nullptr, "tx_pi_merkle_root() never null");
        EXPECT_TRUE(std::memcmp(got_root, root, 32) == 0,
                    "tx_pi_merkle_root bytes round-trip");

        const auto [proof_ptr, proof_len_got] = view.aggregated_proof();
        EXPECT_TRUE(proof_ptr != nullptr, "aggregated_proof ptr non-null");
        EXPECT_EQ(static_cast<long long>(proof_len_got),
                  static_cast<long long>(proof.size()),
                  "aggregated_proof length round-trips");
        EXPECT_TRUE(std::memcmp(proof_ptr, proof.data(), proof.size()) == 0,
                    "aggregated_proof bytes round-trip");

        // Move: ownership transfers, source is left empty. This is a
        // claim the Rust side cannot easily check — it's a pure C++-side
        // RAII invariant.
        BlockExtraView moved = std::move(result.view);
        EXPECT_TRUE(moved.has_payload(), "move target has payload");
        EXPECT_FALSE(result.view.has_payload(),
                     "moved-from view no longer has payload");
        EXPECT_EQ(static_cast<long long>(result.view.n_transfers()), 0LL,
                  "moved-from view reports zero n_transfers");
        EXPECT_TRUE(result.view.aggregated_proof().first == nullptr,
                    "moved-from view aggregated_proof ptr is null");
        EXPECT_EQ(static_cast<long long>(result.view.aggregated_proof().second), 0LL,
                  "moved-from view aggregated_proof len is zero");

        // `moved` goes out of scope here: the RAII free happens exactly
        // once for this allocation. Sanitiser builds catch a double free
        // if we accidentally retained ownership in both views.
    }

    // Free the encoder-side buffer (shares the Plonky3OwnedProof allocator
    // discipline per the FFI docs).
    uno_plonky3_proof_free(wire);
}

// -- Case 3 ------------------------------------------------------------------
// BlockExtraView::decode reject paths.

void case_decode_truncated_buffer() {
    std::fprintf(stderr, "case: decode rejects truncated buffer (<40 B)\n");

    std::uint8_t tiny[16] = {0};
    auto r = BlockExtraView::decode(tiny, sizeof(tiny));
    EXPECT_FALSE(r.has_value(), "decode fails on truncated buffer");
    EXPECT_EQ(static_cast<long long>(r.status),
              static_cast<long long>(VerifyResult::kProofDecodeFailed),
              "truncated → kProofDecodeFailed");
    EXPECT_FALSE(r.view.has_payload(), "view empty on failed decode");

    // Also: zero-length / null buffer.
    auto r2 = BlockExtraView::decode(nullptr, 0);
    EXPECT_FALSE(r2.has_value(), "decode(nullptr, 0) fails");
    EXPECT_EQ(static_cast<long long>(r2.status),
              static_cast<long long>(VerifyResult::kProofDecodeFailed),
              "null/zero → kProofDecodeFailed");
}

void case_decode_bad_scheme_id() {
    std::fprintf(stderr, "case: decode rejects bad scheme_id\n");

    std::uint8_t root[32] = {0};
    for (int i = 0; i < 32; ++i) root[i] = static_cast<std::uint8_t>(i);

    // Build a well-formed v1 blob, then corrupt the scheme_id byte to
    // something the decoder doesn't accept. Layout (from docs §2.3 +
    // UNO_BLOCK_EXTRA_HEADER_BYTES = 40):
    //   [0]      scheme_id  (1 B)
    //   [1]      version    (1 B)
    //   [2..4]   n_transfers (u16 LE, 2 B)
    //   [4..36]  tx_pi_merkle_root (32 B)
    //   [36..40] proof_len (u32 LE, 4 B)
    //   [40..]   proof bytes
    Plonky3OwnedProof wire = encode_v1(/*n_transfers=*/3, root, nullptr, 0);
    EXPECT_TRUE(wire.ptr != nullptr, "encode_v1 produced a wire buffer for empty proof");
    EXPECT_TRUE(wire.len >= 40, "wire has at least the 40-byte header");

    // Corrupt byte 0 to an unaccepted scheme_id (0xFF is not v1).
    wire.ptr[0] = 0xFF;

    auto r = BlockExtraView::decode(wire.ptr, static_cast<std::size_t>(wire.len));
    EXPECT_FALSE(r.has_value(), "decode fails on bad scheme_id");
    EXPECT_EQ(static_cast<long long>(r.status),
              static_cast<long long>(VerifyResult::kProofDecodeFailed),
              "bad scheme_id → kProofDecodeFailed");
    EXPECT_FALSE(r.view.has_payload(), "view empty on failed decode");

    uno_plonky3_proof_free(wire);
}

void case_decode_over_cap_proof_length() {
    std::fprintf(stderr, "case: decode rejects over-cap proof_len\n");

    // Hand-build a 40-byte header that DECLARES an over-cap proof length.
    // We don't actually allocate the tail bytes — the decoder checks the
    // declared length against UNO_BLOCK_EXTRA_MAX_PROOF_BYTES (16 MB)
    // BEFORE touching them.
    std::uint8_t header[40] = {0};
    header[0] = UNO_AGGREGATOR_SCHEME_ID_V1;
    header[1] = UNO_AGGREGATOR_VERSION_V1;
    write_le_u16(&header[2], 0);             // n_transfers = 0
    // tx_pi_merkle_root [4..36]: zeros are fine for this path.
    // proof_len: 32 MB, which is 2x the 16 MB cap.
    const std::uint32_t over_cap =
        2u * static_cast<std::uint32_t>(UNO_BLOCK_EXTRA_MAX_PROOF_BYTES);
    write_le_u32(&header[36], over_cap);

    auto r = BlockExtraView::decode(header, sizeof(header));
    EXPECT_FALSE(r.has_value(), "decode fails on over-cap proof_len");
    EXPECT_EQ(static_cast<long long>(r.status),
              static_cast<long long>(VerifyResult::kLengthTooLarge),
              "over-cap proof_len → kLengthTooLarge");
    EXPECT_FALSE(r.view.has_payload(), "view empty on failed decode");
}

// -- Case 4 ------------------------------------------------------------------
// BlockProofVerifier::verify reject paths.

void case_verify_null_handle() {
    std::fprintf(stderr, "case: verify on un-init'd verifier returns kNullPointer\n");

    BlockProofVerifier v;  // not init()'d.
    EXPECT_FALSE(v.is_initialized(), "un-init'd verifier has null handle");

    UnoBlockPublicInputsView pi{};
    pi.chain_id = CHAIN_ID_TEST;
    pi.block_seqno = 1;
    pi.anchor_seqno = 0;
    pi.n_transfers = 0;
    // tx_pi_merkle_root: zeros.

    const std::uint8_t dummy_proof[4] = {0, 0, 0, 0};
    auto r = v.verify(dummy_proof, sizeof(dummy_proof), pi);
    EXPECT_EQ(static_cast<long long>(r),
              static_cast<long long>(VerifyResult::kNullPointer),
              "null-handle path returns kNullPointer");
}

void case_verify_garbage_proof_bytes() {
    std::fprintf(stderr, "case: verify rejects garbage proof bytes\n");

    BlockProofVerifier v;
    const bool ok = v.init();
    EXPECT_TRUE(ok, "verifier init() succeeds for garbage-proof case");
    if (!ok) return;

    // PI shape: plausible, but we never get to constraint-check — postcard
    // decode of the proof bytes fails first.
    UnoBlockPublicInputsView pi{};
    pi.chain_id = CHAIN_ID_TEST;
    pi.block_seqno = 42;
    pi.anchor_seqno = 41;
    pi.n_transfers = 0;
    for (int i = 0; i < 32; ++i) {
        pi.tx_pi_merkle_root[i] = static_cast<std::uint8_t>(0x55 ^ i);
    }

    // Garbage proof: arbitrary bytes that are obviously not a postcard-
    // encoded Plonky3 proof.
    std::vector<std::uint8_t> garbage(128);
    for (std::size_t i = 0; i < garbage.size(); ++i) {
        garbage[i] = static_cast<std::uint8_t>(0xDE + (i & 0x0F));
    }

    auto r = v.verify(garbage.data(), garbage.size(), pi);
    EXPECT_EQ(static_cast<long long>(r),
              static_cast<long long>(VerifyResult::kProofDecodeFailed),
              "garbage proof → kProofDecodeFailed");

    // Also drive the BlockExtraView overload against an encoded wrapper.
    // The wrapper is well-formed but the inner proof payload is garbage,
    // so the verifier still rejects with kProofDecodeFailed.
    std::uint8_t root[32] = {0};
    Plonky3OwnedProof wire = encode_v1(/*n_transfers=*/0, root,
                                       garbage.data(), garbage.size());
    EXPECT_TRUE(wire.ptr != nullptr, "encode_v1 wrapped garbage proof");
    auto decoded = BlockExtraView::decode(wire.ptr,
                                          static_cast<std::size_t>(wire.len));
    EXPECT_TRUE(decoded.has_value(), "wrapper decode succeeds even for garbage inner");
    if (decoded.has_value()) {
        auto r2 = v.verify(decoded.view, pi);
        EXPECT_EQ(static_cast<long long>(r2),
                  static_cast<long long>(VerifyResult::kProofDecodeFailed),
                  "garbage proof via view → kProofDecodeFailed");
    }
    uno_plonky3_proof_free(wire);
}

// -- Case 5 ------------------------------------------------------------------
// Empty (default-constructed) view behaviour.

void case_empty_view_accessors() {
    std::fprintf(stderr, "case: default-constructed BlockExtraView accessors\n");

    BlockExtraView view;  // empty / not decoded.
    EXPECT_FALSE(view.has_payload(), "default view has no payload");
    EXPECT_EQ(static_cast<long long>(view.scheme_id()), 0LL,
              "empty view scheme_id() returns 0");
    EXPECT_EQ(static_cast<long long>(view.version()), 0LL,
              "empty view version() returns 0");
    EXPECT_EQ(static_cast<long long>(view.n_transfers()), 0LL,
              "empty view n_transfers() returns 0");

    const auto [p, n] = view.aggregated_proof();
    EXPECT_TRUE(p == nullptr, "empty view aggregated_proof ptr is null");
    EXPECT_EQ(static_cast<long long>(n), 0LL,
              "empty view aggregated_proof len is zero");

    // tx_pi_merkle_root() returns a non-null 32-byte region even on empty
    // (it points at the zero-initialised member array).
    const std::uint8_t* root = view.tx_pi_merkle_root();
    EXPECT_TRUE(root != nullptr, "empty view tx_pi_merkle_root() non-null");
    bool all_zero = true;
    for (int i = 0; i < 32; ++i) {
        if (root[i] != 0) { all_zero = false; break; }
    }
    EXPECT_TRUE(all_zero, "empty view tx_pi_merkle_root() is all-zero");

    // Destructor is a no-op on an empty view — no double free risk.
}

}  // namespace

int main() {
    // Skip-guard: if the linked staticlib is a stale build, `init()` fails
    // with an ABI-version mismatch. We detect that up front and print a
    // clear SKIP line rather than a torrent of FAILs, preserving the
    // existing uno/test/* discipline around version-skew.
    {
        BlockProofVerifier probe;
        if (!probe.init()) {
            std::fprintf(stderr,
                         "SKIP: test-block-proof-verifier: BlockProofVerifier::init() "
                         "returned false (ABI version skew between C++ header "
                         "kExpectedAbiVersion=%u and linked uno_plonky3_ffi "
                         "staticlib, or Corrosion not configured). Rebuild the "
                         "Rust staticlib and re-link to run this test.\n",
                         static_cast<unsigned>(uno::crypto::kExpectedAbiVersion));
            return 0;
        }
    }

    case_verifier_lifecycle();
    case_decode_round_trip();
    case_decode_truncated_buffer();
    case_decode_bad_scheme_id();
    case_decode_over_cap_proof_length();
    case_verify_null_handle();
    case_verify_garbage_proof_bytes();
    case_empty_view_accessors();

    std::fprintf(stderr, "\nblock-proof-verifier: passed=%d failed=%d\n",
                 g_passed, g_failed);
    return g_failed == 0 ? 0 : 1;
}
