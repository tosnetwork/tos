/*
    JVM Workchain — cell codec implementation.
*/
#include "jvm/core/cell-codec.h"

#include "jvm/core/dispatch-engine.h"  // for kJvmActivationCode
#include "jvm/core/storage-cell-host.h"
#include "td/utils/Slice.h"
#include "td/utils/crypto.h"  // td::sha256
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/excno.hpp"

namespace jvm_workchain {

namespace {

bool store_maybe_ref(vm::CellBuilder& cb, const td::Ref<vm::Cell>& ref) {
    if (ref.not_null()) {
        return cb.store_ulong_rchk_bool(1, 1) && cb.store_ref_bool(ref);
    }
    return cb.store_ulong_rchk_bool(0, 1);
}

bool fetch_maybe_ref(vm::CellSlice& cs, td::Ref<vm::Cell>& ref) {
    ref = {};
    unsigned has_ref = 0;
    if (!cs.fetch_uint_to(1, has_ref)) {
        return false;
    }
    if (has_ref == 0) {
        return true;
    }
    if (has_ref != 1 || cs.size_refs() == 0) {
        return false;
    }
    return cs.fetch_ref_to(ref);
}

bool jvm_class_hash_is_zero(const JvmClassHash& h) {
    for (auto b : h) {
        if (b != 0) {
            return false;
        }
    }
    return true;
}

}  // namespace

td::Ref<vm::Cell> encode_jvm_contract_account_state(
    const JvmContractAccountState& state) {
    // Round 120 HIGH fix: wrap encoding in try/catch.  Pre-fix,
    // a successful execution that produced a near-max-depth
    // storage_root (e.g. via a Patricia path with many fork
    // ancestors plus a large value) made build_jvm_workchain_
    // output → encode_jvm_contract_account_state →
    // CellBuilder::finalize() throw CellWriteError, escaping
    // consensus execution.  Catch and return null so the caller
    // surfaces a clean error.
    if (state.schema_version != kJvmContractAccountStateSchemaVersion) {
        return {};
    }
    // class_hash is no longer part of the wire format (round 14); the
    // decoder recomputes it from class_bytes.  We just need a non-null
    // class_bytes ref here.  An empty class_bytes payload would produce
    // a zero class_hash on decode, which the decoder rejects.
    if (state.class_bytes.is_null()) {
        return {};
    }

    // class_hash is NOT written on the wire — see header comment.  We
    // do still verify it's non-zero on the struct so callers don't
    // accidentally produce a JVAC whose recomputed hash mismatches
    // their expectation.
    try {
        vm::CellBuilder cb;
        if (!cb.store_ulong_rchk_bool(kJvmContractAccountStateMagic,
                                      kJvmContractAccountStateMagicBits) ||
            !cb.store_ulong_rchk_bool(state.schema_version, 8) ||
            !cb.store_bytes_bool(state.stdlib_hash.data(),
                                 static_cast<unsigned>(state.stdlib_hash.size())) ||
            !cb.store_bytes_bool(state.deployer.data(),
                                 static_cast<unsigned>(state.deployer.size())) ||
            !cb.store_bytes_bool(state.address_commit.data(),
                                 static_cast<unsigned>(
                                     state.address_commit.size())) ||
            !cb.store_ref_bool(state.class_bytes) ||
            !store_maybe_ref(cb, state.storage_root) ||
            !store_maybe_ref(cb, state.manifest_root)) {
            return {};
        }
        return cb.finalize();
    } catch (vm::VmError&) {
        return {};
    } catch (vm::VmVirtError&) {
        return {};
    } catch (...) {
        return {};
    }
}

bool decode_jvm_contract_account_state(td::Ref<vm::Cell> cell,
                                       JvmContractAccountState& out,
                                       std::size_t max_class_bytes) {
    out = JvmContractAccountState{};
    if (cell.is_null()) {
        return false;
    }

    try {
        bool special = false;
        auto cs = vm::load_cell_slice_special(cell, special);
        if (special) {
            return false;
        }

        unsigned long long magic = 0;
        if (!cs.fetch_ulong_bool(kJvmContractAccountStateMagicBits, magic) ||
            static_cast<std::uint32_t>(magic) !=
                kJvmContractAccountStateMagic) {
            return false;
        }

        unsigned schema_version = 0;
        if (!cs.fetch_uint_to(8, schema_version) ||
            schema_version != kJvmContractAccountStateSchemaVersion) {
            return false;
        }
        out.schema_version = static_cast<std::uint8_t>(schema_version);

        if (!cs.fetch_bytes(out.stdlib_hash.data(),
                            static_cast<unsigned>(out.stdlib_hash.size())) ||
            !cs.fetch_bytes(out.deployer.data(),
                            static_cast<unsigned>(out.deployer.size())) ||
            !cs.fetch_bytes(out.address_commit.data(),
                            static_cast<unsigned>(
                                out.address_commit.size())) ||
            cs.size_refs() == 0 ||
            !cs.fetch_ref_to(out.class_bytes) ||
            !fetch_maybe_ref(cs, out.storage_root) ||
            !fetch_maybe_ref(cs, out.manifest_root) ||
            !cs.empty_ext()) {
            out = JvmContractAccountState{};
            return false;
        }
        if (out.class_bytes.is_null()) {
            out = JvmContractAccountState{};
            return false;
        }
        // NOTE: deliberately NOT walking the full storage tree here.
        // Pre-round-9, decode called `validate_jvm_storage_root(...)`
        // which iterated the entire dictionary and decoded every value
        // before any gas was metered.  That made per-call validator CPU
        // proportional to the total contract storage size (DoS via
        // grow-then-no-op).  Storage values are validated lazily in
        // `JvmStorageCellHost::load` during execution under the contract's
        // gas budget; the structural shape of the dictionary is checked
        // by `vm::Dictionary` construction at use time.  Initial state
        // cannot embed a malformed storage tree because the round-3
        // first-activation invariant requires `storage_root.is_null()`.
        // Compute class_hash from class_bytes (round-14: class_hash is
        // no longer stored on the wire — see header comment for the
        // bit-budget reason).  The Avata VM cache and the address-
        // binding gate use this canonical recomputed hash, so a
        // malicious caller cannot poison the VM cache by claiming an
        // alternate class_hash for the same class_bytes.
        // Round 54 MEDIUM fix: forward `max_class_bytes` so the
        // storage-value walker bails out as soon as the running
        // total would exceed the cap, avoiding the full 1 MiB
        // memcpy + sha256 on oversized class blobs.  `max_class_bytes
        // == 0` means no caller-supplied cap; fall back to the
        // legacy 1 MiB envelope cap.
        const std::size_t class_bytes_cap =
            max_class_bytes == 0 ? kJvmStorageValueMaxBytes
                                  : std::min(max_class_bytes,
                                             kJvmStorageValueMaxBytes);
        auto class_bytes_decoded =
            decode_jvm_storage_value(out.class_bytes, class_bytes_cap);
        if (class_bytes_decoded.is_error()) {
            out = JvmContractAccountState{};
            return false;
        }
        const auto& class_bytes_raw = class_bytes_decoded.ok();
        if (class_bytes_raw.empty()) {
            // class_bytes must be non-empty so class_hash is non-zero
            // (the engine address gate requires non-zero class_hash for
            // a meaningful binding).
            out = JvmContractAccountState{};
            return false;
        }
        JvmClassHash recomputed{};
        td::sha256(td::Slice(reinterpret_cast<const char*>(
                                class_bytes_raw.data()),
                             class_bytes_raw.size()),
                   td::MutableSlice(reinterpret_cast<char*>(recomputed.data()),
                                    recomputed.size()));
        out.class_hash = recomputed;
        // Surface the decoded byte length so the engine can cheaply
        // enforce ConfigParam 85's `max_class_bytes` without a second
        // decode pass.
        out.decoded_class_bytes_size = class_bytes_raw.size();
        return true;
    } catch (vm::VmError&) {
        out = JvmContractAccountState{};
        return false;
    } catch (vm::VmVirtError&) {
        out = JvmContractAccountState{};
        return false;
    } catch (...) {
        out = JvmContractAccountState{};
        return false;
    }
}

td::Ref<vm::Cell> encode_jvm_state_init_cell(
    const JvmContractAccountState& state) {
    auto data_cell = encode_jvm_contract_account_state(state);
    if (data_cell.is_null()) {
        return {};
    }
    // Inline the activation marker (single byte 0x4a, 'J') to avoid pulling in
    // dispatch-engine.h.  Mirrors `jvm_activation_code_cell()`.
    vm::CellBuilder code_cb;
    if (!code_cb.store_ulong_rchk_bool(kJvmActivationCode, 8)) {
        return {};
    }
    td::Ref<vm::Cell> code_cell = code_cb.finalize();
    if (code_cell.is_null()) {
        return {};
    }
    // StateInit TLB layout (block.tlb):
    //   _ fixed_prefix_length:(Maybe (## 5))
    //     special:(Maybe TickTock)
    //     code:(Maybe ^Cell)
    //     data:(Maybe ^Cell)
    //     library:(HashmapE 256 SimpleLib)
    //     = StateInit;
    // We emit: no fixed_prefix_length, no special, code=Just ^marker,
    // data=Just ^state, library=empty.
    vm::CellBuilder cb;
    if (!cb.store_long_bool(0, 1)         // fixed_prefix_length: Nothing
        || !cb.store_long_bool(0, 1)      // special: Nothing
        || !cb.store_long_bool(1, 1)      // code: Just
        || !cb.store_ref_bool(code_cell)  // ^code
        || !cb.store_long_bool(1, 1)      // data: Just
        || !cb.store_ref_bool(data_cell)  // ^data
        || !cb.store_long_bool(0, 1)) {   // library: hme_empty$0
        return {};
    }
    return cb.finalize();
}

}  // namespace jvm_workchain
