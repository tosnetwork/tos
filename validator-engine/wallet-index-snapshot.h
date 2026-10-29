/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <functional>
#include <string>

#include "wallet-index.h"

namespace tos_wallet_index {

// Offline transfer limits, enforced before allocation. Existing fixed keys
// are at most 81 bytes. The value ceiling admits the 34 MiB encoding of a
// million deferred candidates plus metadata, with room for cell records.
// A larger record is refused on both export and import, never truncated.
constexpr uint32_t kWalletSnapshotMaxKeyBytes = 1024;
constexpr uint32_t kWalletSnapshotMaxValueBytes = 64u << 20;

struct WalletIndexSnapshotInfo {
  WalletIndexDb::ReplayCheckpoint checkpoint;
  td::Bits256 sha256;
  uint64_t records = 0;
  uint64_t bytes = 0;
};

// A snapshot is a trusted operator's index, not a chain proof. Verification
// requires that operator's digest, obtained independently of the artifact.
// Source ownership is locked during export. Restore writes only a fresh
// sibling staging directory and publishes with an atomic no-replace rename.
using WalletSnapshotCancel = std::function<bool()>;

class WalletIndexSnapshotFile {
 public:
  static td::Result<WalletIndexSnapshotInfo> create(const std::string& index, const std::string& snapshot,
                                                    const WalletSnapshotCancel& cancelled = {});
  static td::Result<WalletIndexSnapshotInfo> verify(const std::string& snapshot, const td::Bits256& expected,
                                                    const WalletSnapshotCancel& cancelled = {});
  static td::Result<WalletIndexSnapshotInfo> restore(const std::string& snapshot, const std::string& index,
                                                     const td::Bits256& expected,
                                                     const WalletSnapshotCancel& cancelled = {});
};

}  // namespace tos_wallet_index
