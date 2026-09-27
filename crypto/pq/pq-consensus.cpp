/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <memory>
#include <openssl/evp.h>

#include "pq-consensus.h"

namespace tos::pq {
namespace {
std::size_t suite_public_key_bytes(PQAlgorithmId a) noexcept {
  return a == PQAlgorithmId::mldsa44 ? mldsa44_public_key_bytes : 0;
}
std::size_t suite_signature_bytes(PQAlgorithmId a) noexcept {
  return a == PQAlgorithmId::mldsa44 ? mldsa44_signature_bytes : 0;
}
}  // namespace

std::optional<std::array<std::uint8_t, 32>> derive_key_id(PQAlgorithmId algorithm_id, std::string_view public_key) {
  // Fail closed before hashing: an unadmitted algorithm, or a public key that is not
  // exactly the suite length, must not be able to produce an identity at all.
  if (!valid_public_key(algorithm_id, public_key)) {
    return std::nullopt;
  }
  // The SHA256_* context functions are deprecated; EVP is the supported interface and
  // digests the same preimage to the same bytes, which the exact key-id vector proves.
  // Every step is checked: an identity derived from a failed hash would be an identity
  // nothing stands behind.
  const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx{EVP_MD_CTX_new(), &EVP_MD_CTX_free};
  if (!ctx) {
    return std::nullopt;
  }
  const auto id = static_cast<std::uint16_t>(algorithm_id);
  const unsigned char id_le[2] = {static_cast<unsigned char>(id & 0xff), static_cast<unsigned char>((id >> 8) & 0xff)};
  std::array<std::uint8_t, 32> out{};
  unsigned int out_len = 0;
  if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(ctx.get(), key_id_domain.data(), key_id_domain.size()) != 1 ||
      EVP_DigestUpdate(ctx.get(), id_le, sizeof id_le) != 1 ||
      EVP_DigestUpdate(ctx.get(), public_key.data(), public_key.size()) != 1 ||
      EVP_DigestFinal_ex(ctx.get(), out.data(), &out_len) != 1 || out_len != out.size()) {
    return std::nullopt;
  }
  return out;
}

bool valid_public_key(PQAlgorithmId algorithm_id, std::string_view public_key) noexcept {
  if (!is_admitted(algorithm_id))
    return false;
  const auto expect = suite_public_key_bytes(algorithm_id);
  return expect != 0 && public_key.size() == expect;
}

bool valid_signature(PQAlgorithmId algorithm_id, std::string_view signature) noexcept {
  if (!is_admitted(algorithm_id))
    return false;
  const auto expect = suite_signature_bytes(algorithm_id);
  return expect != 0 && signature.size() == expect;
}

}  // namespace tos::pq
