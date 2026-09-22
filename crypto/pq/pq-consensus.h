/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once
// PQ-native consensus identity primitives. Pure declarations: the fixed
// ML-DSA-44 lengths, the consensus algorithm id, the consensus key/signature
// value types, and the stable key-id derivation. Encoding to cells (PQBytes) and
// the signer live in separate units; this header carries no backend dependency.
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

#include "mldsa44.h"

namespace tos::pq {

// The one consensus signature suite admitted at genesis. Unknown ids fail closed;
// there is no local algorithm choice and no Ed25519 fallback.
enum class PQAlgorithmId : std::uint16_t { unknown = 0, mldsa44 = 1 };

inline constexpr bool is_admitted(PQAlgorithmId a) noexcept {
  return a == PQAlgorithmId::mldsa44;
}

// Fixed suite lengths (from the vendored backend), promoted into the consensus layer.
struct PQSuite {
  PQAlgorithmId algorithm_id;
  std::size_t public_key_bytes;
  std::size_t signature_bytes;
};
inline constexpr PQSuite mldsa44_suite{PQAlgorithmId::mldsa44, mldsa44_public_key_bytes, mldsa44_signature_bytes};

// Structural hard bounds enforced before allocation/verification. max_certificate_bytes
// is the worst-case a mainnet config must stay within; a config exceeding it is
// rejected deterministically before install (never truncated).
struct PQConsensusLimits {
  PQAlgorithmId algorithm_id = PQAlgorithmId::mldsa44;
  std::size_t public_key_bytes = mldsa44_public_key_bytes;  // 1312
  std::size_t signature_bytes = mldsa44_signature_bytes;    // 2420
  // Provisional structural ceiling for sizing only: 21 is the launch committee,
  // 100/400 are the provisional main/total ceilings. Not a frozen protocol maximum;
  // the binding value comes from ConfigParam16 once the validator-set encoding lands.
  std::size_t max_certificate_signers = 400;
  std::size_t max_main_validators = 100;
  // Framing allowance per signer (validator_id + algorithm_id + cell overhead). This is
  // a generous guess, NOT a measurement of the final encoding.
  std::size_t framing_bytes_per_signer = 64;
  // ESTIMATE ONLY. The real consensus bound must be computed from the final
  // TL-B/PQBytes/BOC encoding of the persisted carrier; nothing may treat this as the frozen bound.
  // Saturates instead of overflowing so a hostile signer count can never wrap.
  std::size_t estimated_certificate_bytes(std::size_t signers) const noexcept {
    const std::size_t per = signature_bytes + framing_bytes_per_signer;
    if (per != 0 && signers > std::numeric_limits<std::size_t>::max() / per) {
      return std::numeric_limits<std::size_t>::max();
    }
    return signers * per;
  }
  std::size_t estimated_max_certificate_bytes() const noexcept {
    return estimated_certificate_bytes(max_certificate_signers);
  }
};

// A validator's consensus public key. key_id is stable-per-key (rotating the PQ key
// changes key_id); the validator_id that stays constant across rotation lives in the
// validator descriptor, not here.
struct ConsensusPQKey {
  PQAlgorithmId algorithm_id{PQAlgorithmId::unknown};
  std::array<std::uint8_t, 32> key_id{};
  std::string public_key;  // exactly public_key_bytes for the suite
  bool operator==(const ConsensusPQKey&) const = default;
};

struct ConsensusPQSignature {
  PQAlgorithmId algorithm_id{PQAlgorithmId::unknown};
  std::string signature;  // exactly signature_bytes for the suite
  bool operator==(const ConsensusPQSignature&) const = default;
};

// Frozen domain-separation constants. These exact strings are normative: they are
// the signing-domain identity of the network and cannot change without a consensus
// format change. The key-id domain binds the algorithm and public key; each signature
// context separates one authority surface from every other ML-DSA use (wallet/agent),
// so a signature produced for one surface never verifies under another.
inline constexpr std::string_view key_id_domain = "TOS-PQ-CONSENSUS-KEY-v1";

// One context per authority surface. All four are frozen here so later work cannot invent a
// new domain later; only the Simplex/finality one has a signer implementation yet.
inline constexpr std::string_view simplex_sign_context = "TOS-CONSENSUS-SIMPLEX-v1";
inline constexpr std::string_view validator_election_context = "TOS-VALIDATOR-ELECTION-v1";
inline constexpr std::string_view validator_config_vote_context = "TOS-VALIDATOR-CONFIG-VOTE-v1";
inline constexpr std::string_view config_admin_context = "TOS-CONFIG-ADMIN-v1";

// key_id = SHA-256(key_id_domain || u16_le(algorithm_id) || public_key), where the
// algorithm id is encoded as exactly two little-endian bytes. Stable for a given
// (algorithm, key) and independent of validator_id.
// Fails closed: an unadmitted algorithm or a public key of the wrong length yields
// no id at all, so an unknown suite can never be given a usable identity.
std::optional<std::array<std::uint8_t, 32>> derive_key_id(PQAlgorithmId algorithm_id, std::string_view public_key);

// Structural validation (size + admitted algorithm). Returns false, never throws, on
// any malformed input; callers fail closed.
bool valid_public_key(PQAlgorithmId algorithm_id, std::string_view public_key) noexcept;
bool valid_signature(PQAlgorithmId algorithm_id, std::string_view signature) noexcept;

}  // namespace tos::pq
