/*
    JVM Workchain — production crypto host adapter.

    Implements the AvataCryptoHost callbacks defined in
    `jvm/avata/include/avata/crypto.h` using the libraries already vendored
    in third-party/: secp256k1 (ECDSA recover/verify), libsodium (SHA-256 +
    Ed25519 verify), and blst (BLS12-381 verify, min-pk arrangement).

    The host is process-singleton: the secp256k1 verification context is a
    pure-function resource (it carries no signing-side state) and is
    created lazily on first use.  Tests can pass `JvmCryptoHost::instance()`
    or wrap it.
*/
#pragma once

#include "jvm/avata/include/avata/crypto.h"

namespace jvm_workchain {

// Build an AvataCryptoHost backed by the production libs.  Returns by
// value; the caller installs via api.set_crypto_host(&host).  Lifetime
// is process-static — the underlying secp256k1 context is created once
// inside the implementation translation unit.
AvataCryptoHost make_production_crypto_host();

}  // namespace jvm_workchain
