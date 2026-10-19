/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

// A key acting in the offline controller-authority domain.
//
// A validator controller's root is what owns the stake, what names the account the
// validator is, and what replaces an operational consensus key. It is therefore the one
// secret that must not be on the machine that validates: a compromised validator should
// cost an operator the key it can rotate, not the authority that rotates it. This store
// exists for operator tooling and is deliberately absent from validator-engine.
//
// It signs under `controller_auth_context` and nothing else. It cannot produce a finality
// signature, a configuration vote or an election signature -- not because those would be
// refused somewhere later, but because there is no method here that makes one. The hot
// `ValidatorPQKeyStore` is the mirror of that: it signs those three and cannot sign a
// controller authorization.
//
// The same type carries the key being *installed*, not only the root. Binding a consensus
// key and rotating a root both require the incoming key to sign the very same
// authorization the root signed, as proof that its private half exists; during that
// ceremony the incoming seed is in the offline domain too, before it is provisioned to
// the validator host. One type, one domain, one thing it can sign.

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

#include "pq-consensus.h"

namespace tos::pq {

class ValidatorControllerRootKeyStore {
 public:
  ValidatorControllerRootKeyStore(ValidatorControllerRootKeyStore&&) noexcept;
  ValidatorControllerRootKeyStore& operator=(ValidatorControllerRootKeyStore&&) noexcept;
  ~ValidatorControllerRootKeyStore();

  // Fresh root keypair from a secure random 32-byte seed; nullopt on RNG/backend failure.
  static std::optional<ValidatorControllerRootKeyStore> generate() noexcept;
  // Deterministic keypair from a caller-owned 32-byte seed.
  static std::optional<ValidatorControllerRootKeyStore> from_seed(std::string_view seed) noexcept;

  const ConsensusPQKey& root_key() const noexcept {
    return key_;
  }

  // Sign one controller authorization: the 93 bytes of `controller_auth_preimage`, under
  // `controller_auth_context`. The message is the commitment the contract rebuilds from
  // its own address and the request's fields; this signs it and decides nothing about it.
  //
  // nullopt on backend failure; the returned signature is always signature_bytes long.
  std::optional<ConsensusPQSignature> sign_controller_authorization(std::string_view message) const noexcept;

 private:
  ValidatorControllerRootKeyStore() = default;
  struct Secret;
  ConsensusPQKey key_{};
  std::unique_ptr<Secret> secret_;  // wiped on destruction
};

}  // namespace tos::pq
