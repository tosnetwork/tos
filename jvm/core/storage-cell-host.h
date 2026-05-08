/*
    JVM Workchain — cell-backed Storage host adapter.

    Avata's java.lang.Storage native API reads and writes 32-byte slots
    with arbitrary byte values.  This adapter stores those slots in a
    TOS Dictionary so the chain compute adapter can expose the
    per-contract `JvmContractAccountState.storage_root` through
    avata_set_storage_host().
*/
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

#include "td/utils/Status.h"
#include "vm/cells.h"
#include "vm/dict.h"

struct AvataStorageHost;

namespace jvm_workchain {

constexpr std::size_t kJvmStorageSlotBytes = 32;
constexpr std::size_t kJvmStorageValueChunkBytes = 127;
constexpr std::size_t kJvmStorageValueMaxBytes = 1024 * 1024;

using JvmStorageSlot = std::array<std::uint8_t, kJvmStorageSlotBytes>;
using JvmStorageValue = std::vector<std::uint8_t>;

class JvmStorageCellHost {
 public:
    JvmStorageCellHost();
    explicit JvmStorageCellHost(td::Ref<vm::Cell> root);

    td::Ref<vm::Cell> root_cell() const;

    td::Result<std::optional<JvmStorageValue>> load(
        const JvmStorageSlot& slot) const;
    td::Status store(const JvmStorageSlot& slot, const JvmStorageValue& value);
    td::Status clear(const JvmStorageSlot& slot);
    td::Status begin_transaction();
    td::Status commit_transaction();
    td::Status rollback_transaction();

    // Enumerate key-value pairs in order.  The callback receives (slot, value)
    // and should return true to continue or false to stop early.  Stops after
    // limit entries; a limit of 0 means no entries are visited.
    static constexpr std::size_t kEnumerateDefaultLimit = 100;
    td::Status enumerate_slots(
        const std::function<bool(const JvmStorageSlot&, const JvmStorageValue&)>& cb,
        std::size_t limit = kEnumerateDefaultLimit) const;

 private:
    mutable vm::Dictionary dict_;
    std::vector<td::Ref<vm::Cell>> snapshots_;
};

td::Ref<vm::Cell> encode_jvm_storage_value(const JvmStorageValue& value);
td::Result<JvmStorageValue> decode_jvm_storage_value(td::Ref<vm::Cell> root);

// Validate the full storage dictionary shape.  This is intended for import,
// test, and defensive state-boundary checks; hot compute paths can bind the
// root lazily and let first-touch reads surface malformed values.
bool validate_jvm_storage_root(td::Ref<vm::Cell> root);

// Fill an AvataStorageHost with callbacks backed by `storage`. The caller
// remains responsible for calling avata_set_storage_host()/clear around the
// interpreter invocation.
void configure_avata_storage_host(JvmStorageCellHost& storage,
                                  AvataStorageHost& host);

}  // namespace jvm_workchain
