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
  // Untrusted import only: records kept (account history) and dropped
  // (everything the importing node derives itself).
  uint64_t kept = 0;
  uint64_t dropped = 0;
};

// A restored snapshot is a trusted operator's index, not a chain proof:
// verify and restore require that operator's digest, obtained independently
// of the artifact. An untrusted import instead keeps only what the importing
// node can check against its own chain.
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
  // Import a snapshot from a publisher that is not trusted. No digest is
  // needed: only the account history rows, the schema and the replay
  // checkpoint are kept, everything else is dropped, and the new index is
  // Quarantined. The index service must check it against the local node's
  // own head before anything in it is served.
  static td::Result<WalletIndexSnapshotInfo> import_untrusted(const std::string& snapshot, const std::string& index,
                                                              const WalletSnapshotCancel& cancelled = {});

 private:
  static td::Result<WalletIndexSnapshotInfo> import_staged(const std::string& snapshot, const std::string& index,
                                                           const td::Bits256* expected,
                                                           const WalletSnapshotCancel& cancelled);
};

}  // namespace tos_wallet_index
