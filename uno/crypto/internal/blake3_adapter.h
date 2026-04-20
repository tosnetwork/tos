/*
    Uno Workchain — BLAKE3 adapter (internal).

    BLAKE3 usage in the crypto module:
      - hybrid-kem transcript        (§2.7)
      - nonce derivation             (§2.7)
      - tx_hash (consumed by Agent 1's transaction.cpp, provided here)
      - filter-tag input is Poseidon2, NOT BLAKE3 — do not confuse.

    Two candidate backends, pick at compile time:
      - UNO_BLAKE3_AVATAR: include "at/crypto/at_blake3.h", call
        at_blake3_hash(data, sz, out).
      - UNO_BLAKE3_REFERENCE: vendor `third-party/blake3/blake3.h` and call
        the reference API.

    The adapter exposes ONE function:

        void blake3_hash(td::Slice in, uint8_t out[32]);

    all callers in this module use the exact 32-byte output form.
*/
#pragma once

#include <cstdint>
#include "td/utils/Slice.h"

namespace uno_workchain::crypto::internal {

/// One-shot BLAKE3: writes 32 bytes of hash output to `out`.
void blake3_hash(td::Slice in, uint8_t out[32]);

/// Streaming helper so callers can concatenate fields without allocating
/// an intermediate buffer. Use-case: the hybrid-kem transcript.
struct Blake3Hasher {
    Blake3Hasher();
    ~Blake3Hasher();
    Blake3Hasher(const Blake3Hasher&) = delete;
    Blake3Hasher& operator=(const Blake3Hasher&) = delete;

    void update(td::Slice data);
    void finalize_32(uint8_t out[32]);

  private:
    // Opaque backend state (sized to cover at_blake3_t OR the reference
    // struct, whichever Agent 5 picks). 4 KiB is comfortably above both.
    alignas(128) unsigned char state_[4096];
};

}  // namespace uno_workchain::crypto::internal
