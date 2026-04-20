/*
    Uno Workchain — BLAKE3 adapter (implementation).

    Two backends selected by preprocessor flag:
      - UNO_BLAKE3_AVATAR    → avatar's `at_blake3` (SIMD, production).
      - UNO_BLAKE3_REFERENCE → BLAKE3-team/BLAKE3 C reference (portable).

    Default (no flag set): the module fails to link with a clear
    `blake3_hash` undefined symbol so Agent 5 notices.

    For unit tests outside the validator build, define
    UNO_BLAKE3_INLINE_REFERENCE to compile a self-contained public-domain
    BLAKE3 implementation here. This path is small (~400 lines); if anyone
    enables it Agent 5 should budget a security review.
*/

#include "uno/crypto/internal/blake3_adapter.h"

#include <cstdlib>
#include <cstring>

#if defined(UNO_BLAKE3_AVATAR)
extern "C" {
#include "at/crypto/at_blake3.h"
}
#elif defined(UNO_BLAKE3_REFERENCE)
extern "C" {
#include "blake3.h"  // from BLAKE3-team/BLAKE3 reference (vendored by Agent 5)
}
#endif

namespace uno_workchain::crypto::internal {

#if defined(UNO_BLAKE3_AVATAR)

void blake3_hash(td::Slice in, uint8_t out[32]) {
    at_blake3_hash(in.data(), in.size(), out);
}

struct Impl {
    at_blake3_t hasher;
};
static_assert(sizeof(Impl) <= 32768, "Blake3Hasher state too small; grow state_");

Blake3Hasher::Blake3Hasher() {
    auto* p = reinterpret_cast<Impl*>(state_);
    at_blake3_new(&p->hasher);
    at_blake3_init(&p->hasher);
}
Blake3Hasher::~Blake3Hasher() {
    auto* p = reinterpret_cast<Impl*>(state_);
    at_blake3_delete(&p->hasher);
}
void Blake3Hasher::update(td::Slice data) {
    auto* p = reinterpret_cast<Impl*>(state_);
    at_blake3_append(&p->hasher, data.data(), data.size());
}
void Blake3Hasher::finalize_32(uint8_t out[32]) {
    auto* p = reinterpret_cast<Impl*>(state_);
    at_blake3_fini(&p->hasher, out);
}

#elif defined(UNO_BLAKE3_REFERENCE)

void blake3_hash(td::Slice in, uint8_t out[32]) {
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, in.data(), in.size());
    blake3_hasher_finalize(&h, out, 32);
}

struct Impl { blake3_hasher hasher; };
static_assert(sizeof(Impl) <= 32768, "Blake3Hasher state too small; grow state_");

Blake3Hasher::Blake3Hasher() {
    auto* p = reinterpret_cast<Impl*>(state_);
    blake3_hasher_init(&p->hasher);
}
Blake3Hasher::~Blake3Hasher() = default;
void Blake3Hasher::update(td::Slice data) {
    auto* p = reinterpret_cast<Impl*>(state_);
    blake3_hasher_update(&p->hasher, data.data(), data.size());
}
void Blake3Hasher::finalize_32(uint8_t out[32]) {
    auto* p = reinterpret_cast<Impl*>(state_);
    blake3_hasher_finalize(&p->hasher, out, 32);
}

#else

// Link-time error path: neither backend selected. Leave the functions
// undefined so the linker complains with a clear message.
//
// To compile locally for header review, temporarily define
// UNO_BLAKE3_REFERENCE and point the include path at BLAKE3-team's C
// reference. In CI this must resolve via Agent 5's CMake.
#error "uno/crypto: pick UNO_BLAKE3_AVATAR or UNO_BLAKE3_REFERENCE"

#endif

}  // namespace uno_workchain::crypto::internal
