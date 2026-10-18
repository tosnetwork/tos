/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <functional>
#include <memory>
#include <string>

#include "td/actor/coro_task.h"
#include "td/utils/Time.h"
#include "td/utils/buffer.h"
#include "validator/interfaces/persistent-state.h"

namespace tos::validator {

struct BootstrapStateStatus {
  BlockIdExt id;
  bool ready{false};
  std::string reason{"snapshot_not_found"};
  UnixTime gen_utime{0};
  // Persistent-state expiry of the snapshot files.
  UnixTime expires_at{0};
  double archive_ttl{0};
  // When ordinary archive retention may first delete a package holding a
  // proof the snapshot needs: the earliest first-masterchain-block time of
  // those packages plus archive_ttl. Zero unless ready.
  UnixTime archive_expires_at{0};
};

// An archived block proof, with the package that serves it.
struct ArchivedProof {
  RootHash state_root;
  // Generation time of the first masterchain block in the ordinary archive
  // package that holds the proof; archive retention ages the package by it.
  UnixTime package_start{0};
};

// The reader is deliberately restricted to archive reads. No wait-for-state,
// download, state import or metadata write belongs in a readiness query.
struct BootstrapStateReader {
  // Holds the manager's admission slot until the underlying reads settle, even
  // if the client's deadline has already delivered a timeout response.
  std::shared_ptr<void> lease;
  std::function<td::actor::Task<ArchivedProof>(BlockIdExt)> archived_proof;
  std::function<td::actor::Task<td::uint64>(BlockIdExt, BlockIdExt, PersistentStateType)> state_size;
  std::function<td::actor::Task<td::BufferSlice>(BlockIdExt, BlockIdExt, PersistentStateType, td::int64, td::int64)>
      state_slice;
  std::function<td::actor::Task<td::Unit>(BlockIdExt)> zero_state;
};

// A description identifies the required files; it is never evidence that those
// files have finished serialization. The same checker runs against the serving
// archive in production and a controlled archive reader in native tests.
td::actor::Task<BootstrapStateStatus> check_bootstrap_state(td::Ref<PersistentStateDescription> description,
                                                            double archive_ttl, UnixTime now,
                                                            BootstrapStateReader reader, td::Timestamp deadline);

}  // namespace tos::validator
