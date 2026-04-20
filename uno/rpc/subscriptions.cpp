/*
    Uno Workchain — subscription-manager implementation.
    Mirrors evm/rpc/subscriptions.cpp in shape and thread-safety model.
*/
#include "uno/rpc/subscriptions.h"

#include <cstdio>

namespace uno_workchain {

namespace {

UnoSubscriptionManager g_uno_sub_manager;

std::string make_dec_u64(uint64_t v) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "%llu", (unsigned long long)v);
    return buf;
}

void cap_events(UnoSubscription& sub) {
    if (sub.pending_events.size() > kMaxPendingEventsPerUnoSub) {
        sub.pending_events.erase(
            sub.pending_events.begin(),
            sub.pending_events.begin() + static_cast<std::ptrdiff_t>(
                sub.pending_events.size() - kMaxPendingEventsPerUnoSub));
    }
}

}  // namespace

UnoSubscriptionManager& global_uno_subscription_manager() {
    return g_uno_sub_manager;
}

uint64_t UnoSubscriptionManager::subscribe(UnoSubscriptionType type) {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t id = next_id_++;
    UnoSubscription sub;
    sub.id = id;
    sub.type = type;
    subscriptions_[id] = std::move(sub);
    return id;
}

bool UnoSubscriptionManager::unsubscribe(uint64_t sub_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    return subscriptions_.erase(sub_id) > 0;
}

std::vector<UnoSubscriptionEvent> UnoSubscriptionManager::poll(uint64_t sub_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = subscriptions_.find(sub_id);
    if (it == subscriptions_.end()) return {};
    auto events = std::move(it->second.pending_events);
    it->second.pending_events.clear();
    return events;
}

void UnoSubscriptionManager::notify_included_tx(const std::string& tx_hash_hex,
                                                 uint64_t           block_seqno,
                                                 uint64_t           fee_nano) {
    // NOTE(uno-api-v0): payload fields chosen to mirror §9.1's
    // uno_getTransactionStatus return shape — { tx_hash, block_seqno, fee }.
    std::string json = "{";
    json += "\"tx_hash\":\"" + tx_hash_hex + "\",";
    json += "\"block_seqno\":" + make_dec_u64(block_seqno) + ",";
    json += "\"fee\":" + make_dec_u64(fee_nano);
    json += "}";

    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [id, sub] : subscriptions_) {
        if (sub.type == UnoSubscriptionType::IncludedTx) {
            sub.pending_events.push_back(UnoSubscriptionEvent{json});
            cap_events(sub);
        }
    }
}

void UnoSubscriptionManager::notify_new_head(uint64_t           block_seqno,
                                              const std::string& anchor_root_hex,
                                              uint64_t           tx_count,
                                              uint64_t           note_count) {
    std::string json = "{";
    json += "\"seqno\":" + make_dec_u64(block_seqno) + ",";
    json += "\"anchor_root\":\"" + anchor_root_hex + "\",";
    json += "\"tx_count\":" + make_dec_u64(tx_count) + ",";
    json += "\"note_count\":" + make_dec_u64(note_count);
    json += "}";

    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [id, sub] : subscriptions_) {
        if (sub.type == UnoSubscriptionType::NewHead) {
            sub.pending_events.push_back(UnoSubscriptionEvent{json});
            cap_events(sub);
        }
    }
}

void UnoSubscriptionManager::notify_new_anchor(uint64_t           block_seqno,
                                                const std::string& anchor_root_hex) {
    std::string json = "{";
    json += "\"seqno\":" + make_dec_u64(block_seqno) + ",";
    json += "\"anchor_root\":\"" + anchor_root_hex + "\"";
    json += "}";

    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [id, sub] : subscriptions_) {
        if (sub.type == UnoSubscriptionType::NewAnchor) {
            sub.pending_events.push_back(UnoSubscriptionEvent{json});
            cap_events(sub);
        }
    }
}

void UnoSubscriptionManager::reset_for_test() {
    std::lock_guard<std::mutex> lock(mutex_);
    subscriptions_.clear();
    next_id_ = 1;
}

}  // namespace uno_workchain
