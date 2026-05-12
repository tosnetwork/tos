/*
    JVM Workchain — deterministic outbound-action host adapter
    implementation.
*/
#include "jvm/core/message-host.h"

#include <cstring>
#include <utility>

#include "block/block.h"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "common/bigint.hpp"
#include "common/refint.h"
#include "jvm/avata/include/avata/message.h"
#include "jvm/core/storage-cell-host.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/excno.hpp"

namespace jvm_workchain {

namespace {

int message_send_callback(void* user,
                          std::int32_t dest_workchain,
                          const unsigned char* dest_addr,
                          const unsigned char* value_be,
                          const unsigned char* body,
                          std::size_t body_length) {
    if (user == nullptr
        || dest_addr == nullptr
        || value_be == nullptr
        || (body_length != 0 && body == nullptr)
        || body_length > kJvmMessageBodyMaxBytes) {
        return AVATA_MESSAGE_ERROR;
    }
    if (dest_workchain < -128 || dest_workchain > 127) {
        return AVATA_MESSAGE_ERROR;
    }

    std::array<std::uint8_t, kJvmMessageAddressBytes> addr{};
    std::memcpy(addr.data(), dest_addr, kJvmMessageAddressBytes);

    std::array<std::uint8_t, kJvmMessageValueBytes> value{};
    std::memcpy(value.data(), value_be, kJvmMessageValueBytes);

    std::vector<std::uint8_t> body_vec;
    body_vec.resize(body_length);
    if (body_length != 0) {
        std::memcpy(body_vec.data(), body, body_length);
    }

    auto status = static_cast<JvmMessageHost*>(user)->send(
        dest_workchain, addr, value, body_vec);
    return status.is_ok() ? AVATA_MESSAGE_OK : AVATA_MESSAGE_ERROR;
}

int message_create_account_callback(void* user,
                                     const unsigned char* dest_addr,
                                     const unsigned char* state_init_boc,
                                     std::size_t state_init_boc_length,
                                     const unsigned char* value_be,
                                     const unsigned char* body,
                                     std::size_t body_length) {
    if (user == nullptr
        || dest_addr == nullptr
        || value_be == nullptr
        || state_init_boc == nullptr
        || state_init_boc_length == 0
        || state_init_boc_length > kJvmStateInitBocMaxBytes
        || (body_length != 0 && body == nullptr)
        || body_length > kJvmMessageBodyMaxBytes) {
        return AVATA_MESSAGE_ERROR;
    }

    std::array<std::uint8_t, kJvmMessageAddressBytes> addr{};
    std::memcpy(addr.data(), dest_addr, kJvmMessageAddressBytes);

    std::array<std::uint8_t, kJvmMessageValueBytes> value{};
    std::memcpy(value.data(), value_be, kJvmMessageValueBytes);

    std::vector<std::uint8_t> state_init_vec;
    state_init_vec.resize(state_init_boc_length);
    std::memcpy(state_init_vec.data(), state_init_boc, state_init_boc_length);

    std::vector<std::uint8_t> body_vec;
    body_vec.resize(body_length);
    if (body_length != 0) {
        std::memcpy(body_vec.data(), body, body_length);
    }

    auto status = static_cast<JvmMessageHost*>(user)->create_account(
        addr, state_init_vec, value, body_vec);
    return status.is_ok() ? AVATA_MESSAGE_OK : AVATA_MESSAGE_ERROR;
}

int message_begin_transaction_callback(void* user) {
    if (user == nullptr) {
        return AVATA_MESSAGE_ERROR;
    }
    auto status = static_cast<JvmMessageHost*>(user)->begin_transaction();
    return status.is_ok() ? AVATA_MESSAGE_OK : AVATA_MESSAGE_ERROR;
}

int message_commit_transaction_callback(void* user) {
    if (user == nullptr) {
        return AVATA_MESSAGE_ERROR;
    }
    auto status = static_cast<JvmMessageHost*>(user)->commit_transaction();
    return status.is_ok() ? AVATA_MESSAGE_OK : AVATA_MESSAGE_ERROR;
}

int message_rollback_transaction_callback(void* user) {
    if (user == nullptr) {
        return AVATA_MESSAGE_ERROR;
    }
    auto status = static_cast<JvmMessageHost*>(user)->rollback_transaction();
    return status.is_ok() ? AVATA_MESSAGE_OK : AVATA_MESSAGE_ERROR;
}

td::Ref<vm::Cell> empty_cell() {
    vm::CellBuilder cb;
    return cb.finalize();
}

td::Ref<vm::CellSlice> build_dest_addr_csr(std::int32_t workchain,
                                           const std::uint8_t* addr) {
    vm::CellBuilder cb;
    if (!cb.store_long_bool(4, 3)                  // addr_std$10 anycast=Nothing
        || !cb.store_long_rchk_bool(workchain, 8)
        || !cb.store_bits_bool(td::ConstBitPtr(addr), 256)) {
        return {};
    }
    auto cell = cb.finalize();
    return vm::load_cell_slice_ref(std::move(cell));
}

td::Ref<vm::CellSlice> build_src_addr_none_csr() {
    vm::CellBuilder cb;
    if (!cb.store_long_bool(0, 2)) {
        return {};
    }
    auto cell = cb.finalize();
    return vm::load_cell_slice_ref(std::move(cell));
}

td::Ref<vm::CellSlice> build_value_csr(
    const std::array<std::uint8_t, kJvmMessageValueBytes>& value_be) {
    td::RefInt256 tomis = td::make_refint();
    if (!tomis.write().import_bytes(value_be.data(),
                                     value_be.size(),
                                     /*sgnd=*/false)) {
        return {};
    }
    vm::CellBuilder cb;
    if (!block::store_CurrencyCollection(cb, std::move(tomis), {})) {
        return {};
    }
    auto cell = cb.finalize();
    return vm::load_cell_slice_ref(std::move(cell));
}

// Pack a Uint256 big-endian as `VarUInteger 16` (the Tomis type used
// by action_create_account#4a435241.value).  Mirrors the C++ host's
// `block::tlb::t_Tomis.store_integer_ref` path.
td::Ref<vm::CellSlice> build_tomis_csr(
    const std::array<std::uint8_t, kJvmMessageValueBytes>& value_be) {
    td::RefInt256 tomis = td::make_refint();
    if (!tomis.write().import_bytes(value_be.data(),
                                     value_be.size(),
                                     /*sgnd=*/false)) {
        return {};
    }
    vm::CellBuilder cb;
    if (!block::tlb::t_Tomis.store_integer_ref(cb, std::move(tomis))) {
        return {};
    }
    auto cell = cb.finalize();
    return vm::load_cell_slice_ref(std::move(cell));
}

td::Ref<vm::CellSlice> zero_grams_csr() {
    vm::CellBuilder cb;
    if (!cb.store_long_bool(0, 4)) {
        return {};
    }
    auto cell = cb.finalize();
    return vm::load_cell_slice_ref(std::move(cell));
}

td::Ref<vm::Cell> build_body_cell(const std::vector<std::uint8_t>& body) {
    vm::CellBuilder cb;
    if (body.empty()) {
        return cb.finalize();
    }
    return encode_jvm_storage_value(body);
}

td::Ref<vm::Cell> encode_send_action(const JvmOutboundAction& msg) {
    auto dest = build_dest_addr_csr(msg.dest_workchain, msg.dest_addr.data());
    auto src = build_src_addr_none_csr();
    auto value = build_value_csr(msg.value_be);
    auto fees = zero_grams_csr();
    if (dest.is_null() || src.is_null()
        || value.is_null() || fees.is_null()) {
        return {};
    }

    auto body = build_body_cell(msg.body);
    if (body.is_null()) {
        return {};
    }

    block::gen::CommonMsgInfoRelaxed::Record_int_msg_info info;
    info.ihr_disabled = true;
    info.bounce = false;
    info.bounced = false;
    info.src = src;
    info.dest = dest;
    info.value = value;
    info.fwd_fee = fees;
    info.extra_flags = fees;
    info.created_lt = 0;
    info.created_at = 0;

    td::Ref<vm::CellSlice> info_csr;
    if (!tlb::csr_pack(info_csr, info)) {
        return {};
    }

    vm::CellBuilder init_cb;
    if (!init_cb.store_long_bool(0, 1)) {
        return {};
    }
    td::Ref<vm::CellSlice> init_csr = init_cb.as_cellslice_ref();

    vm::CellBuilder body_cb;
    if (!body_cb.store_long_bool(1, 1)
        || !body_cb.store_ref_bool(body)) {
        return {};
    }
    td::Ref<vm::CellSlice> body_csr = body_cb.as_cellslice_ref();

    block::gen::MessageRelaxed::Record relaxed;
    relaxed.info = info_csr;
    relaxed.init = init_csr;
    relaxed.body = body_csr;

    vm::CellBuilder msg_cb;
    td::Ref<vm::Cell> msg_cell;
    if (!tlb::type_pack(msg_cb, block::gen::t_MessageRelaxed_Any, relaxed)
        || !msg_cb.finalize_to(msg_cell)) {
        return {};
    }

    vm::CellBuilder action_cb;
    if (!action_cb.store_ulong_rchk_bool(0x0ec3c86d, 32)
        || !action_cb.store_ulong_rchk_bool(0, 8)
        || !action_cb.store_ref_bool(std::move(msg_cell))) {
        return {};
    }
    return action_cb.finalize();
}

td::Ref<vm::Cell> encode_create_account_action(
    const JvmOutboundAction& act) {
    // Parse the caller-supplied StateInit BOC.  We do NOT validate
    // its full TLB shape here — the host action phase
    // (try_action_create_account) re-validates downstream; rejecting
    // a malformed BOC up-front simply produces a cleaner error path.
    td::Ref<vm::Cell> state_init_cell;
    try {
        auto parsed = vm::std_boc_deserialize(td::Slice(
            reinterpret_cast<const char*>(act.state_init_boc.data()),
            act.state_init_boc.size()));
        if (parsed.is_error()) {
            return {};
        }
        state_init_cell = parsed.move_as_ok();
    } catch (...) {
        return {};
    }
    if (state_init_cell.is_null()) {
        return {};
    }

    auto value_csr = build_tomis_csr(act.value_be);
    if (value_csr.is_null()) {
        return {};
    }

    // body:(Maybe ^Cell).  Empty body → Nothing (1 bit "0"); non-empty
    // → Just ^body (1 bit "1" + ref).
    td::Ref<vm::Cell> body_cell;
    if (!act.body.empty()) {
        body_cell = build_body_cell(act.body);
        if (body_cell.is_null()) {
            return {};
        }
    }

    // action_create_account#4a435241 mode:(## 8)
    //     dest_addr:bits256
    //     state_init:^StateInit
    //     value:Tomis
    //     body:(Maybe ^Cell)
    vm::CellBuilder cb;
    if (!cb.store_ulong_rchk_bool(0x4a435241, 32)        // tag
        || !cb.store_ulong_rchk_bool(0, 8)               // mode = 0
        || !cb.store_bits_bool(td::ConstBitPtr(act.dest_addr.data()), 256)
        || !cb.store_ref_bool(std::move(state_init_cell))
        || !cb.append_cellslice_bool(*value_csr)) {
        return {};
    }
    if (body_cell.not_null()) {
        if (!cb.store_long_bool(1, 1)
            || !cb.store_ref_bool(std::move(body_cell))) {
            return {};
        }
    } else {
        if (!cb.store_long_bool(0, 1)) {
            return {};
        }
    }
    return cb.finalize();
}

}  // namespace

const std::vector<JvmOutboundAction>& JvmMessageHost::actions() const {
    return actions_;
}

const std::vector<JvmOutboundAction>& JvmMessageHost::messages() const {
    return actions_;
}

td::Status JvmMessageHost::send(
    std::int32_t dest_workchain,
    const std::array<std::uint8_t, kJvmMessageAddressBytes>& dest_addr,
    const std::array<std::uint8_t, kJvmMessageValueBytes>& value_be,
    const std::vector<std::uint8_t>& body) {
    if (body.size() > kJvmMessageBodyMaxBytes) {
        return td::Status::Error("JVM outbound message body exceeds limit");
    }
    if (actions_.size() >= kJvmOutboundActionCountMax) {
        return td::Status::Error(
            "JVM outbound action count exceeds per-tx limit of "
            + std::to_string(kJvmOutboundActionCountMax));
    }
    if (dest_workchain < -128 || dest_workchain > 127) {
        return td::Status::Error(
            "JVM outbound message destination workchain out of int8 range");
    }

    JvmOutboundAction act;
    act.kind = JvmOutboundActionKind::SendMessage;
    act.dest_workchain = dest_workchain;
    act.dest_addr = dest_addr;
    act.value_be = value_be;
    act.body = body;
    actions_.push_back(std::move(act));
    return td::Status::OK();
}

td::Status JvmMessageHost::create_account(
    const std::array<std::uint8_t, kJvmMessageAddressBytes>& dest_addr,
    const std::vector<std::uint8_t>& state_init_boc,
    const std::array<std::uint8_t, kJvmMessageValueBytes>& value_be,
    const std::vector<std::uint8_t>& body) {
    if (state_init_boc.empty()) {
        return td::Status::Error(
            "JVM outbound createAccount stateInit must not be empty");
    }
    if (state_init_boc.size() > kJvmStateInitBocMaxBytes) {
        return td::Status::Error(
            "JVM outbound createAccount stateInit exceeds limit");
    }
    if (body.size() > kJvmMessageBodyMaxBytes) {
        return td::Status::Error(
            "JVM outbound createAccount body exceeds limit");
    }
    if (actions_.size() >= kJvmOutboundActionCountMax) {
        return td::Status::Error(
            "JVM outbound action count exceeds per-tx limit of "
            + std::to_string(kJvmOutboundActionCountMax));
    }

    JvmOutboundAction act;
    act.kind = JvmOutboundActionKind::CreateAccount;
    act.dest_addr = dest_addr;
    act.value_be = value_be;
    act.body = body;
    act.state_init_boc = state_init_boc;
    actions_.push_back(std::move(act));
    return td::Status::OK();
}

td::Status JvmMessageHost::begin_transaction() {
    snapshots_.push_back(actions_.size());
    return td::Status::OK();
}

td::Status JvmMessageHost::commit_transaction() {
    if (snapshots_.empty()) {
        return td::Status::Error("JVM message commit without transaction");
    }
    snapshots_.pop_back();
    return td::Status::OK();
}

td::Status JvmMessageHost::rollback_transaction() {
    if (snapshots_.empty()) {
        return td::Status::Error("JVM message rollback without transaction");
    }
    const auto size = snapshots_.back();
    snapshots_.pop_back();
    actions_.resize(size);
    return td::Status::OK();
}

void configure_avata_message_host(JvmMessageHost& messages,
                                  AvataMessageHost& host) {
    host = {};
    host.user = &messages;
    host.send = message_send_callback;
    host.createAccount = message_create_account_callback;
    host.beginTransaction = message_begin_transaction_callback;
    host.commitTransaction = message_commit_transaction_callback;
    host.rollbackTransaction = message_rollback_transaction_callback;
}

td::Ref<vm::Cell> encode_jvm_outbound_action(const JvmOutboundAction& act) {
    try {
        switch (act.kind) {
            case JvmOutboundActionKind::SendMessage:
                return encode_send_action(act);
            case JvmOutboundActionKind::CreateAccount:
                return encode_create_account_action(act);
        }
        return {};
    } catch (vm::VmError&) {
        return {};
    } catch (vm::VmVirtError&) {
        return {};
    } catch (...) {
        return {};
    }
}

td::Ref<vm::Cell> build_jvm_combined_action_list(
    td::Ref<vm::Cell> event_action_list,
    const std::vector<JvmOutboundAction>& outbound_actions) {
    try {
        td::Ref<vm::Cell> list = event_action_list.not_null()
                                     ? std::move(event_action_list)
                                     : empty_cell();
        for (const auto& act : outbound_actions) {
            auto encoded = encode_jvm_outbound_action(act);
            if (encoded.is_null()) {
                return {};
            }
            vm::CellSlice encoded_cs = vm::load_cell_slice(encoded);
            vm::CellBuilder cb;
            if (!cb.store_ref_bool(list)
                || !cb.append_cellslice_bool(std::move(encoded_cs))) {
                return {};
            }
            list = cb.finalize();
        }
        return list;
    } catch (vm::VmError&) {
        return {};
    } catch (vm::VmVirtError&) {
        return {};
    } catch (...) {
        return {};
    }
}

}  // namespace jvm_workchain
