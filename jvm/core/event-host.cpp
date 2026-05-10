/*
    JVM Workchain — deterministic event host adapter implementation.
*/
#include "jvm/core/event-host.h"

#include <cstring>
#include <utility>

#include "jvm/avata/include/avata/event.h"
#include "jvm/core/storage-cell-host.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/excno.hpp"

namespace jvm_workchain {

namespace {

int event_emit_callback(void* user,
                        const unsigned char* topics,
                        std::size_t topic_count,
                        const unsigned char* data,
                        std::size_t data_length) {
    if (user == nullptr ||
        topic_count > AVATA_EVENT_MAX_TOPICS ||
        (topic_count != 0 && topics == nullptr) ||
        (data_length != 0 && data == nullptr) ||
        data_length > kJvmEventDataMaxBytes) {
        return AVATA_EVENT_ERROR;
    }

    std::vector<JvmEventTopic> event_topics;
    event_topics.resize(topic_count);
    for (std::size_t i = 0; i < topic_count; ++i) {
        std::memcpy(event_topics[i].data(),
                    topics + i * AVATA_EVENT_TOPIC_SIZE,
                    AVATA_EVENT_TOPIC_SIZE);
    }

    JvmEventData event_data;
    event_data.resize(data_length);
    if (data_length != 0) {
        std::memcpy(event_data.data(), data, data_length);
    }

    auto status = static_cast<JvmEventHost*>(user)->emit(
        event_topics, event_data);
    return status.is_ok() ? AVATA_EVENT_OK : AVATA_EVENT_ERROR;
}

int event_begin_transaction_callback(void* user) {
    if (user == nullptr) {
        return AVATA_EVENT_ERROR;
    }
    auto status = static_cast<JvmEventHost*>(user)->begin_transaction();
    return status.is_ok() ? AVATA_EVENT_OK : AVATA_EVENT_ERROR;
}

int event_commit_transaction_callback(void* user) {
    if (user == nullptr) {
        return AVATA_EVENT_ERROR;
    }
    auto status = static_cast<JvmEventHost*>(user)->commit_transaction();
    return status.is_ok() ? AVATA_EVENT_OK : AVATA_EVENT_ERROR;
}

int event_rollback_transaction_callback(void* user) {
    if (user == nullptr) {
        return AVATA_EVENT_ERROR;
    }
    auto status = static_cast<JvmEventHost*>(user)->rollback_transaction();
    return status.is_ok() ? AVATA_EVENT_OK : AVATA_EVENT_ERROR;
}

td::Ref<vm::Cell> empty_cell() {
    vm::CellBuilder cb;
    return cb.finalize();
}

td::Ref<vm::Cell> encode_topic_list(
    const std::vector<JvmEventTopic>& topics) {
    td::Ref<vm::Cell> list = empty_cell();
    for (std::size_t i = topics.size(); i-- > 0;) {
        vm::CellBuilder cb;
        if (!cb.store_ref_bool(list) ||
            !cb.store_bytes_bool(topics[i].data(),
                                 static_cast<unsigned>(topics[i].size()))) {
            return {};
        }
        list = cb.finalize();
    }
    return list;
}

td::Result<std::vector<JvmEventTopic>> decode_topic_list(
    td::Ref<vm::Cell> cell,
    std::size_t topic_count) {
    if (cell.is_null() || topic_count > kJvmEventMaxTopics) {
        return td::Status::Error("JVM event topic list is malformed");
    }

    std::vector<JvmEventTopic> topics;
    topics.reserve(topic_count);
    try {
        for (std::size_t i = 0; i < topic_count; ++i) {
            bool special = false;
            auto cs = vm::load_cell_slice_special(cell, special);
            if (special || cs.size() != kJvmEventTopicBytes * 8 ||
                cs.size_refs() != 1) {
                return td::Status::Error("JVM event topic node is malformed");
            }

            auto prev = cs.fetch_ref();
            JvmEventTopic topic{};
            if (!cs.fetch_bytes(topic.data(),
                                static_cast<unsigned>(topic.size())) ||
                !cs.empty_ext()) {
                return td::Status::Error("JVM event topic bytes are malformed");
            }
            topics.push_back(topic);
            cell = std::move(prev);
        }

        bool special = false;
        auto cs = vm::load_cell_slice_special(cell, special);
        if (special || cs.size() != 0 || cs.size_refs() != 0) {
            return td::Status::Error("JVM event topic list has trailing nodes");
        }
        return topics;
    } catch (vm::VmError&) {
        return td::Status::Error("JVM event topic list decode hit vm::VmError");
    } catch (vm::VmVirtError&) {
        return td::Status::Error("JVM event topic list decode hit vm::VmVirtError");
    } catch (...) {
        return td::Status::Error("JVM event topic list decode failed");
    }
}

td::Ref<vm::Cell> encode_event_destination(const JvmEvent& event) {
    JvmEventTopic destination{};
    if (!event.topics.empty()) {
        destination = event.topics.front();
    }
    vm::CellBuilder cb;
    if (!cb.store_ulong_rchk_bool(1, 2) ||
        !cb.store_ulong_rchk_bool(kJvmEventTopicBytes * 8, 9) ||
        !cb.store_bytes_bool(destination.data(),
                             static_cast<unsigned>(destination.size()))) {
        return {};
    }
    return cb.finalize();
}

}  // namespace

const std::vector<JvmEvent>& JvmEventHost::events() const {
    return events_;
}

td::Status JvmEventHost::emit(const std::vector<JvmEventTopic>& topics,
                              const JvmEventData& data) {
    if (topics.size() > kJvmEventMaxTopics ||
        data.size() > kJvmEventDataMaxBytes) {
        return td::Status::Error("JVM event exceeds configured limits");
    }

    JvmEvent event;
    event.topics = topics;
    event.data = data;
    events_.push_back(std::move(event));
    return td::Status::OK();
}

td::Status JvmEventHost::begin_transaction() {
    snapshots_.push_back(events_.size());
    return td::Status::OK();
}

td::Status JvmEventHost::commit_transaction() {
    if (snapshots_.empty()) {
        return td::Status::Error("JVM event commit without transaction");
    }
    snapshots_.pop_back();
    return td::Status::OK();
}

td::Status JvmEventHost::rollback_transaction() {
    if (snapshots_.empty()) {
        return td::Status::Error("JVM event rollback without transaction");
    }
    const auto size = snapshots_.back();
    snapshots_.pop_back();
    events_.resize(size);
    return td::Status::OK();
}

void configure_avata_event_host(JvmEventHost& events, AvataEventHost& host) {
    host = {};
    host.user = &events;
    host.emit = event_emit_callback;
    host.beginTransaction = event_begin_transaction_callback;
    host.commitTransaction = event_commit_transaction_callback;
    host.rollbackTransaction = event_rollback_transaction_callback;
}

td::Ref<vm::Cell> encode_jvm_event_payload(const JvmEvent& event) {
    if (event.topics.size() > kJvmEventMaxTopics ||
        event.data.size() > kJvmEventDataMaxBytes) {
        return {};
    }

    auto topics = encode_topic_list(event.topics);
    auto data = encode_jvm_storage_value(event.data);
    if (topics.is_null() || data.is_null()) {
        return {};
    }

    vm::CellBuilder cb;
    if (!cb.store_ulong_rchk_bool(kJvmEventPayloadMagic, 32) ||
        !cb.store_ulong_rchk_bool(kJvmEventPayloadSchemaVersion, 8) ||
        !cb.store_ulong_rchk_bool(event.topics.size(), 8) ||
        !cb.store_ulong_rchk_bool(event.data.size(), 32) ||
        !cb.store_ref_bool(std::move(topics)) ||
        !cb.store_ref_bool(std::move(data))) {
        return {};
    }
    return cb.finalize();
}

td::Result<JvmEvent> decode_jvm_event_payload(td::Ref<vm::Cell> cell) {
    if (cell.is_null()) {
        return td::Status::Error("JVM event payload is null");
    }

    try {
        bool special = false;
        auto cs = vm::load_cell_slice_special(std::move(cell), special);
        if (special) {
            return td::Status::Error("JVM event payload is special");
        }

        unsigned long long magic = 0;
        unsigned schema_version = 0;
        unsigned topic_count = 0;
        unsigned long long data_length = 0;
        if (!cs.fetch_ulong_bool(32, magic) ||
            static_cast<std::uint32_t>(magic) != kJvmEventPayloadMagic ||
            !cs.fetch_uint_to(8, schema_version) ||
            schema_version != kJvmEventPayloadSchemaVersion ||
            !cs.fetch_uint_to(8, topic_count) ||
            topic_count > kJvmEventMaxTopics ||
            !cs.fetch_ulong_bool(32, data_length) ||
            data_length > kJvmEventDataMaxBytes ||
            cs.size() != 0 ||
            cs.size_refs() != 2) {
            return td::Status::Error("JVM event payload header is malformed");
        }

        auto topic_root = cs.fetch_ref();
        auto data_root = cs.fetch_ref();
        TRY_RESULT(topics, decode_topic_list(std::move(topic_root),
                                             topic_count));
        TRY_RESULT(data, decode_jvm_storage_value(std::move(data_root)));
        if (data.size() != data_length) {
            return td::Status::Error("JVM event payload data length mismatch");
        }

        JvmEvent event;
        event.topics = std::move(topics);
        event.data = std::move(data);
        return event;
    } catch (vm::VmError&) {
        return td::Status::Error("JVM event payload decode hit vm::VmError");
    } catch (vm::VmVirtError&) {
        return td::Status::Error("JVM event payload decode hit vm::VmVirtError");
    } catch (...) {
        return td::Status::Error("JVM event payload decode failed");
    }
}

td::Ref<vm::Cell> encode_jvm_event_message(const JvmEvent& event) {
    auto body = encode_jvm_event_payload(event);
    if (body.is_null()) {
        return {};
    }
    auto dest = encode_event_destination(event);
    if (dest.is_null()) {
        return {};
    }
    auto dest_cs = vm::load_cell_slice(std::move(dest));

    vm::CellBuilder cb;
    if (!cb.store_ulong_rchk_bool(12, 4) ||      // ext_out + empty source
        !cb.append_cellslice_bool(std::move(dest_cs)) ||
        !cb.store_ulong_rchk_bool(0, 64) ||      // created_lt, rewritten later
        !cb.store_ulong_rchk_bool(0, 32) ||      // created_at, rewritten later
        !cb.store_ulong_rchk_bool(0, 1) ||       // no StateInit
        !cb.store_ulong_rchk_bool(1, 1) ||       // body is stored by reference
        !cb.store_ref_bool(std::move(body))) {
        return {};
    }
    return cb.finalize();
}

td::Ref<vm::Cell> build_jvm_event_action_list(
    const std::vector<JvmEvent>& events) {
    // Round 120 HIGH fix: wrap in try/catch.  16 events with
    // max-depth payloads cross vm::CellTraits::max_depth at
    // CellBuilder::finalize(), throwing CellWriteError.  This is
    // reached from avata-execution.cpp before a td::Status can be
    // returned; converting to a null result lets the caller surface
    // a clean error.
    try {
        td::Ref<vm::Cell> list = empty_cell();
        for (const auto& event : events) {
            auto msg = encode_jvm_event_message(event);
            if (msg.is_null()) {
                return {};
            }

            vm::CellBuilder cb;
            if (!cb.store_ref_bool(list) ||
                !cb.store_ulong_rchk_bool(0x0ec3c86d, 32) ||
                !cb.store_ulong_rchk_bool(0, 8) ||
                !cb.store_ref_bool(std::move(msg))) {
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
