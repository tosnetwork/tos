/*
    JVM Workchain — cell-backed Storage host adapter implementation.
*/
#include "jvm/core/storage-cell-host.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>

#include "jvm/avata/include/avata/storage.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/excno.hpp"

namespace jvm_workchain {

namespace {

td::ConstBitPtr slot_bits(const JvmStorageSlot& slot) {
    return td::ConstBitPtr{slot.data()};
}

JvmStorageSlot make_slot(const unsigned char slot[AVATA_STORAGE_SLOT_SIZE]) {
    JvmStorageSlot out{};
    std::memcpy(out.data(), slot, out.size());
    return out;
}

td::Ref<vm::Cell> encode_empty_value() {
    vm::CellBuilder cb;
    if (!cb.store_ulong_rchk_bool(0, 1)) {
        return {};
    }
    return cb.finalize();
}

int storage_load_callback(void* user,
                          const unsigned char slot[AVATA_STORAGE_SLOT_SIZE],
                          unsigned char** value,
                          std::size_t* value_length) {
    if (user == nullptr || slot == nullptr || value == nullptr ||
        value_length == nullptr) {
        return AVATA_STORAGE_ERROR;
    }
    auto* storage = static_cast<JvmStorageCellHost*>(user);
    auto loaded = storage->load(make_slot(slot));
    if (loaded.is_error()) {
        return AVATA_STORAGE_ERROR;
    }
    auto maybe_value = loaded.move_as_ok();
    if (!maybe_value.has_value()) {
        *value = nullptr;
        *value_length = 0;
        return AVATA_STORAGE_OK;
    }

    *value_length = maybe_value->size();
    if (maybe_value->empty()) {
        auto* bytes = static_cast<unsigned char*>(std::malloc(1));
        if (bytes == nullptr) {
            return AVATA_STORAGE_ERROR;
        }
        *value = bytes;
        return AVATA_STORAGE_OK;
    }
    auto* bytes = static_cast<unsigned char*>(std::malloc(maybe_value->size()));
    if (bytes == nullptr) {
        *value_length = 0;
        return AVATA_STORAGE_ERROR;
    }
    std::memcpy(bytes, maybe_value->data(), maybe_value->size());
    *value = bytes;
    return AVATA_STORAGE_OK;
}

int storage_store_callback(void* user,
                           const unsigned char slot[AVATA_STORAGE_SLOT_SIZE],
                           const unsigned char* value,
                           std::size_t value_length) {
    if (user == nullptr || slot == nullptr ||
        (value == nullptr && value_length != 0)) {
        return AVATA_STORAGE_ERROR;
    }
    JvmStorageValue bytes;
    bytes.resize(value_length);
    if (value_length != 0) {
        std::memcpy(bytes.data(), value, value_length);
    }
    auto status = static_cast<JvmStorageCellHost*>(user)->store(
        make_slot(slot), bytes);
    return status.is_ok() ? AVATA_STORAGE_OK : AVATA_STORAGE_ERROR;
}

int storage_clear_callback(void* user,
                           const unsigned char slot[AVATA_STORAGE_SLOT_SIZE]) {
    if (user == nullptr || slot == nullptr) {
        return AVATA_STORAGE_ERROR;
    }
    auto status = static_cast<JvmStorageCellHost*>(user)->clear(make_slot(slot));
    return status.is_ok() ? AVATA_STORAGE_OK : AVATA_STORAGE_ERROR;
}

void storage_free_value_callback(void* /*user*/, unsigned char* value) {
    std::free(value);
}

int storage_begin_transaction_callback(void* user) {
    if (user == nullptr) {
        return AVATA_STORAGE_ERROR;
    }
    auto status = static_cast<JvmStorageCellHost*>(user)->begin_transaction();
    return status.is_ok() ? AVATA_STORAGE_OK : AVATA_STORAGE_ERROR;
}

int storage_commit_transaction_callback(void* user) {
    if (user == nullptr) {
        return AVATA_STORAGE_ERROR;
    }
    auto status = static_cast<JvmStorageCellHost*>(user)->commit_transaction();
    return status.is_ok() ? AVATA_STORAGE_OK : AVATA_STORAGE_ERROR;
}

int storage_rollback_transaction_callback(void* user) {
    if (user == nullptr) {
        return AVATA_STORAGE_ERROR;
    }
    auto status = static_cast<JvmStorageCellHost*>(user)->rollback_transaction();
    return status.is_ok() ? AVATA_STORAGE_OK : AVATA_STORAGE_ERROR;
}

}  // namespace

td::Ref<vm::Cell> encode_jvm_storage_value(const JvmStorageValue& value) {
    if (value.size() > kJvmStorageValueMaxBytes) {
        return {};
    }
    if (value.empty()) {
        return encode_empty_value();
    }

    td::Ref<vm::Cell> next;
    const std::size_t chunks =
        (value.size() + kJvmStorageValueChunkBytes - 1) /
        kJvmStorageValueChunkBytes;
    for (std::size_t i = chunks; i-- > 0;) {
        const std::size_t start = i * kJvmStorageValueChunkBytes;
        const std::size_t end =
            std::min(start + kJvmStorageValueChunkBytes, value.size());
        const std::size_t len = end - start;

        vm::CellBuilder cb;
        if (!cb.store_bytes_bool(value.data() + start,
                                 static_cast<unsigned>(len))) {
            return {};
        }
        if (next.not_null()) {
            if (!cb.store_ulong_rchk_bool(1, 1) ||
                !cb.store_ref_bool(std::move(next))) {
                return {};
            }
        } else if (!cb.store_ulong_rchk_bool(0, 1)) {
            return {};
        }
        next = cb.finalize();
    }
    return next;
}

td::Result<JvmStorageValue> decode_jvm_storage_value(td::Ref<vm::Cell> root) {
    JvmStorageValue out;
    if (root.is_null()) {
        return td::Status::Error("JVM storage value root is null");
    }

    try {
        auto cell = std::move(root);
        for (std::size_t chunks = 0; chunks <= kJvmStorageValueMaxBytes /
                                          kJvmStorageValueChunkBytes + 1;
             ++chunks) {
            if (cell.is_null()) {
                return td::Status::Error("JVM storage value chain ended early");
            }

            bool special = false;
            auto cs = vm::load_cell_slice_special(cell, special);
            if (special) {
                return td::Status::Error("JVM storage value cell is special");
            }

            const unsigned bits = cs.size();
            if (bits < 1 || ((bits - 1) % 8) != 0) {
                return td::Status::Error("JVM storage value cell is not byte-aligned");
            }
            const unsigned byte_count = (bits - 1) / 8;
            if (byte_count > kJvmStorageValueChunkBytes ||
                out.size() > kJvmStorageValueMaxBytes - byte_count) {
                return td::Status::Error("JVM storage value exceeds maximum size");
            }

            const std::size_t offset = out.size();
            out.resize(offset + byte_count);
            if (byte_count != 0 &&
                !cs.fetch_bytes(out.data() + offset, byte_count)) {
                return td::Status::Error("JVM storage value bytes are truncated");
            }

            unsigned has_next = 0;
            if (!cs.fetch_uint_to(1, has_next) || has_next > 1) {
                return td::Status::Error("JVM storage value has malformed next tag");
            }
            if (has_next == 0) {
                if (cs.size_refs() != 0 || !cs.empty_ext()) {
                    return td::Status::Error("JVM storage value has trailing data");
                }
                return out;
            }
            if (cs.size() != 0 || cs.size_refs() != 1) {
                return td::Status::Error("JVM storage value has malformed next ref");
            }
            cell = cs.fetch_ref();
        }
    } catch (vm::VmError&) {
        return td::Status::Error("JVM storage value decode hit vm::VmError");
    } catch (vm::VmVirtError&) {
        return td::Status::Error("JVM storage value decode hit vm::VmVirtError");
    } catch (...) {
        return td::Status::Error("JVM storage value decode failed");
    }

    return td::Status::Error("JVM storage value chain is too deep");
}

JvmStorageCellHost::JvmStorageCellHost() : dict_(256) {
}

JvmStorageCellHost::JvmStorageCellHost(td::Ref<vm::Cell> root)
    : dict_(std::move(root), 256) {
}

td::Ref<vm::Cell> JvmStorageCellHost::root_cell() const {
    return dict_.get_root_cell();
}

td::Result<std::optional<JvmStorageValue>> JvmStorageCellHost::load(
    const JvmStorageSlot& slot) const {
    try {
        auto value_ref = dict_.lookup_ref(slot_bits(slot), 256);
        if (value_ref.is_null()) {
            return std::optional<JvmStorageValue>{};
        }
        TRY_RESULT(value, decode_jvm_storage_value(std::move(value_ref)));
        return std::optional<JvmStorageValue>{std::move(value)};
    } catch (vm::VmError&) {
        return td::Status::Error("JVM storage root lookup hit vm::VmError");
    } catch (vm::VmVirtError&) {
        return td::Status::Error("JVM storage root lookup hit vm::VmVirtError");
    } catch (...) {
        return td::Status::Error("JVM storage root lookup failed");
    }
}

td::Status JvmStorageCellHost::store(const JvmStorageSlot& slot,
                                     const JvmStorageValue& value) {
    auto cell = encode_jvm_storage_value(value);
    if (cell.is_null()) {
        return td::Status::Error("JVM storage value encode failed");
    }
    try {
        if (!dict_.set_ref(slot_bits(slot), 256, std::move(cell))) {
            return td::Status::Error("JVM storage dictionary set failed");
        }
        return td::Status::OK();
    } catch (vm::VmError&) {
        return td::Status::Error("JVM storage dictionary set hit vm::VmError");
    } catch (vm::VmVirtError&) {
        return td::Status::Error("JVM storage dictionary set hit vm::VmVirtError");
    } catch (...) {
        return td::Status::Error("JVM storage dictionary set failed");
    }
}

td::Status JvmStorageCellHost::clear(const JvmStorageSlot& slot) {
    try {
        (void)dict_.lookup_delete(slot_bits(slot), 256);
        return td::Status::OK();
    } catch (vm::VmError&) {
        return td::Status::Error("JVM storage dictionary clear hit vm::VmError");
    } catch (vm::VmVirtError&) {
        return td::Status::Error("JVM storage dictionary clear hit vm::VmVirtError");
    } catch (...) {
        return td::Status::Error("JVM storage dictionary clear failed");
    }
}

td::Status JvmStorageCellHost::begin_transaction() {
    snapshots_.push_back(dict_.get_root_cell());
    return td::Status::OK();
}

td::Status JvmStorageCellHost::commit_transaction() {
    if (snapshots_.empty()) {
        return td::Status::Error("JVM storage commit without transaction");
    }
    snapshots_.pop_back();
    return td::Status::OK();
}

td::Status JvmStorageCellHost::rollback_transaction() {
    if (snapshots_.empty()) {
        return td::Status::Error("JVM storage rollback without transaction");
    }
    auto root = std::move(snapshots_.back());
    snapshots_.pop_back();
    dict_ = vm::Dictionary(std::move(root), 256);
    return td::Status::OK();
}

bool validate_jvm_storage_root(td::Ref<vm::Cell> root) {
    if (root.is_null()) {
        return true;
    }
    try {
        bool special = false;
        (void)vm::load_cell_slice_special(root, special);
        if (special) {
            return false;
        }

        vm::Dictionary dict(std::move(root), 256);
        bool ok = true;
        const bool walked = dict.check_for_each(
            [&ok](td::Ref<vm::CellSlice> value,
                  td::ConstBitPtr /*key*/,
                  int key_bits) -> bool {
                if (key_bits != 256 || value.is_null() ||
                    value->size() != 0 || value->size_refs() != 1) {
                    ok = false;
                    return false;
                }
                auto decoded =
                    decode_jvm_storage_value(value->prefetch_ref(0));
                if (decoded.is_error()) {
                    ok = false;
                    return false;
                }
                return true;
            });
        return walked && ok;
    } catch (vm::VmError&) {
        return false;
    } catch (vm::VmVirtError&) {
        return false;
    } catch (...) {
        return false;
    }
}

void configure_avata_storage_host(JvmStorageCellHost& storage,
                                  AvataStorageHost& host) {
    host.user = &storage;
    host.load = storage_load_callback;
    host.store = storage_store_callback;
    host.clear = storage_clear_callback;
    host.freeValue = storage_free_value_callback;
    host.beginTransaction = storage_begin_transaction_callback;
    host.commitTransaction = storage_commit_transaction_callback;
    host.rollbackTransaction = storage_rollback_transaction_callback;
}

td::Status JvmStorageCellHost::enumerate_slots(
    const std::function<bool(const JvmStorageSlot&, const JvmStorageValue&)>& cb,
    std::size_t limit) const {
    if (limit == 0) return td::Status::OK();

    // Use get_minmax_key to seed the iteration at the smallest key, then
    // advance with lookup_nearest_key(fetch_next=true, allow_eq=false).
    JvmStorageSlot key_buf{};
    td::Ref<vm::CellSlice> cs;
    try {
        cs = dict_.get_minmax_key(td::BitPtr{key_buf.data()}, 256);
    } catch (...) {
        return td::Status::Error("JVM storage enumeration start failed");
    }

    std::size_t count = 0;
    while (cs.not_null() && count < limit) {
        if (cs->size() != 0 || cs->size_refs() != 1) {
            return td::Status::Error("JVM storage enumeration found malformed entry");
        }
        TRY_RESULT(value, decode_jvm_storage_value(cs->prefetch_ref(0)));
        if (!cb(key_buf, value)) break;
        ++count;
        try {
            cs = dict_.lookup_nearest_key(td::BitPtr{key_buf.data()}, 256, true, false);
        } catch (...) {
            return td::Status::Error("JVM storage enumeration advance failed");
        }
    }
    return td::Status::OK();
}

}  // namespace jvm_workchain
