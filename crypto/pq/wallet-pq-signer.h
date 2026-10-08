/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace tos::pq {
enum class WalletPQRole { primary, rescue };
enum class WalletPQPurpose { auth, pop, preparation };

// In-memory cryptographic backend only. Callers must approve the exact request,
// prove current wallet policy and protect custody/backup before invoking it.
// No classical algorithm, caller-defined context, file persistence or seed export.
class WalletPQSigner {
 public:
  WalletPQSigner(WalletPQSigner&&) noexcept;
  WalletPQSigner& operator=(WalletPQSigner&&) noexcept;
  WalletPQSigner(const WalletPQSigner&) = delete;
  WalletPQSigner& operator=(const WalletPQSigner&) = delete;
  ~WalletPQSigner();
  static std::optional<WalletPQSigner> generate(WalletPQRole role);
  // Recovery boundary: caller retains responsibility for wiping the input seed.
  // ML-DSA uses 32 bytes; SLH uses independent 16-byte SK.seed/SK.prf/PK.seed.
  static std::optional<WalletPQSigner> from_seed(WalletPQRole role, std::string_view seed);
  const std::string& public_key() const noexcept {
    return public_key_;
  }
  WalletPQRole role() const noexcept {
    return role_;
  }
  // Exactly the 32-byte digest produced by the immutable SDK request encoder.
  // Randomized Pure signing with protocol-fixed context, followed by verification.
  std::optional<std::string> sign(WalletPQPurpose purpose, std::string_view digest) const;

 private:
  WalletPQSigner();
  struct Secret;
  std::unique_ptr<Secret> secret_;
  WalletPQRole role_{WalletPQRole::primary};
  std::string public_key_;
};
}  // namespace tos::pq
