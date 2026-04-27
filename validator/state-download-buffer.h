/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

#include <memory>

#include "td/utils/buffer.h"
#include "td/utils/int_types.h"

namespace tos {
namespace validator {
namespace fullnode {

// RAII reservation against the global persistent-state download memory
// budget. The reservation is held by a shared_ptr alongside the downloaded
// buffer; the underlying bytes are returned to the global budget only when
// the last reference is dropped (i.e., when downstream consumers have
// finished processing the buffer).
//
// Declared here in a public header (independent of the DownloadState actor
// implementation) so that both the network-side producer and every
// manager/full-node interface boundary can carry the reservation through
// without breaking the reservation lifetime invariant.
struct PersistentStateDownloadReservation {
  td::uint64 bytes{0};

  PersistentStateDownloadReservation() = default;
  explicit PersistentStateDownloadReservation(td::uint64 b) : bytes(b) {
  }
  PersistentStateDownloadReservation(const PersistentStateDownloadReservation &) = delete;
  PersistentStateDownloadReservation &operator=(const PersistentStateDownloadReservation &) = delete;
  PersistentStateDownloadReservation(PersistentStateDownloadReservation &&) = delete;
  PersistentStateDownloadReservation &operator=(PersistentStateDownloadReservation &&) = delete;
  ~PersistentStateDownloadReservation();
};

// Pairs a downloaded persistent-state buffer with its budget reservation.
// As long as a BudgetedBufferSlice (or any copy of `reservation`) is held,
// the corresponding bytes remain accounted against the global budget. The
// reservation is released exactly once when the last shared_ptr ref is
// dropped.
struct BudgetedBufferSlice {
  td::BufferSlice data;
  std::shared_ptr<PersistentStateDownloadReservation> reservation;
};

// RAII reservation against the global persistent-state PROCESSING memory
// budget. This budget is separate from the download budget: it accounts the
// transient extra memory required while parsing/persisting a downloaded
// state buffer (e.g. the BufferSlice clone fed to `create_shard_state`).
//
// The two budgets must be tracked separately because the download budget
// covers the resident original buffer while it is held alive across the
// network -> manager -> disk-write pipeline; the processing budget covers
// the additional clone(s) that exist only during deserialize/validate.
// Mixing them would either over-restrict downloads (counting transient
// peaks against the download cap) or under-account the actual peak
// resident bytes (the audit's M-01 finding: 256 MiB advertised state with
// real peak closer to 512-768 MiB).
struct PersistentStateProcessingReservation {
  td::uint64 bytes{0};

  PersistentStateProcessingReservation() = default;
  explicit PersistentStateProcessingReservation(td::uint64 b) : bytes(b) {
  }
  PersistentStateProcessingReservation(const PersistentStateProcessingReservation &) = delete;
  PersistentStateProcessingReservation &operator=(const PersistentStateProcessingReservation &) = delete;
  PersistentStateProcessingReservation(PersistentStateProcessingReservation &&) = delete;
  PersistentStateProcessingReservation &operator=(PersistentStateProcessingReservation &&) = delete;
  ~PersistentStateProcessingReservation();
};

// Production-side reservation API for the processing budget. Returns true
// iff `size` bytes were CAS'd into the global counter; in that case the
// caller MUST own a `PersistentStateProcessingReservation{size}` whose
// destructor will release the bytes exactly once. Zero-byte requests are
// always admitted as a no-op.
bool try_reserve_persistent_state_processing_memory(td::uint64 size);

namespace testing {

// Test-only handle to the global persistent-state download budget. These
// helpers exist so a unit test can exercise the reservation lifetime
// invariant without bringing up the full DownloadState actor stack.
td::uint64 test_get_persistent_state_download_bytes();
bool test_try_reserve_persistent_state_download_memory(td::uint64 size);

// Test-only handle to the global persistent-state processing budget.
// Mirrors the download counterpart so the parse/persist clone accounting
// can be validated without standing up the DownloadShardState actor.
td::uint64 test_get_persistent_state_processing_bytes();
bool test_try_reserve_persistent_state_processing_memory(td::uint64 size);

}  // namespace testing

}  // namespace fullnode
}  // namespace validator
}  // namespace tos
