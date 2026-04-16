/*
    EVM Workchain — subscription manager implementation.
    Source: TOS-specific adapter.
*/
#include "evm-subscriptions.h"

#include <cstdio>

namespace evm_workchain {

static SubscriptionManager g_sub_manager;

SubscriptionManager& global_subscription_manager() {
    return g_sub_manager;
}

uint64_t SubscriptionManager::subscribe(SubscriptionType type,
                                         const LogSubscriptionFilter& filter) {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t id = next_id_++;
    Subscription sub;
    sub.id = id;
    sub.type = type;
    sub.log_filter = filter;
    subscriptions_[id] = std::move(sub);
    return id;
}

bool SubscriptionManager::unsubscribe(uint64_t sub_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    return subscriptions_.erase(sub_id) > 0;
}

std::vector<SubscriptionEvent> SubscriptionManager::poll(uint64_t sub_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = subscriptions_.find(sub_id);
    if (it == subscriptions_.end()) return {};
    auto events = std::move(it->second.pending_events);
    it->second.pending_events.clear();
    return events;
}

// --- Helper: format hex ---

static std::string hex_addr(const evmc::address& addr) {
    char buf[43];
    snprintf(buf, sizeof(buf), "\"0x");
    for (int i = 0; i < 20; i++) snprintf(buf + 3 + i*2, 3, "%02x", addr.bytes[i]);
    strcat(buf, "\"");
    return buf;
}

static std::string hex_bytes32(const evmc::bytes32& h) {
    char buf[67];
    snprintf(buf, sizeof(buf), "\"0x");
    for (int i = 0; i < 32; i++) snprintf(buf + 3 + i*2, 3, "%02x", h.bytes[i]);
    strcat(buf, "\"");
    return buf;
}

static std::string hex_u64(uint64_t v) {
    char buf[32];
    if (v == 0) return "\"0x0\"";
    snprintf(buf, sizeof(buf), "\"0x%lx\"", (unsigned long)v);
    return buf;
}

// --- Notifications ---

void SubscriptionManager::notify_new_head(const StoredBlock& block) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Build newHead JSON (same format as eth_getBlockByNumber result)
    std::string json = "{";
    json += "\"number\":" + hex_u64(block.number) + ",";
    json += "\"hash\":" + hex_bytes32(block.hash) + ",";
    json += "\"parentHash\":" + hex_bytes32(block.parent_hash) + ",";
    json += "\"timestamp\":" + hex_u64(block.timestamp) + ",";
    json += "\"gasLimit\":" + hex_u64(block.gas_limit) + ",";
    json += "\"gasUsed\":" + hex_u64(block.gas_used) + ",";
    json += "\"miner\":" + hex_addr(block.miner);
    json += "}";

    for (auto& [id, sub] : subscriptions_) {
        if (sub.type == SubscriptionType::NewHeads) {
            sub.pending_events.push_back(SubscriptionEvent{json});
        }
    }
}

static bool log_matches_filter(const silkworm::Log& log,
                                const LogSubscriptionFilter& filter) {
    // Address filter
    if (!filter.addresses.empty()) {
        bool found = false;
        for (const auto& addr : filter.addresses) {
            if (log.address == addr) { found = true; break; }
        }
        if (!found) return false;
    }
    // Topic filter
    for (size_t i = 0; i < filter.topics.size(); ++i) {
        if (filter.topics[i].empty()) continue;
        if (i >= log.topics.size()) return false;
        bool found = false;
        for (const auto& t : filter.topics[i]) {
            if (log.topics[i] == t) { found = true; break; }
        }
        if (!found) return false;
    }
    return true;
}

void SubscriptionManager::notify_logs(uint64_t block_number,
                                       const evmc::bytes32& tx_hash,
                                       const std::vector<silkworm::Log>& logs) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (size_t log_idx = 0; log_idx < logs.size(); ++log_idx) {
        const auto& log = logs[log_idx];

        // Build log JSON
        std::string json = "{";
        json += "\"address\":" + hex_addr(log.address) + ",";
        json += "\"topics\":[";
        for (size_t j = 0; j < log.topics.size(); ++j) {
            if (j > 0) json += ",";
            json += hex_bytes32(log.topics[j]);
        }
        json += "],";
        json += "\"data\":\"0x";
        for (auto b : log.data) { char h[3]; snprintf(h, 3, "%02x", b); json += h; }
        json += "\",";
        json += "\"blockNumber\":" + hex_u64(block_number) + ",";
        json += "\"transactionHash\":" + hex_bytes32(tx_hash) + ",";
        json += "\"logIndex\":" + hex_u64(static_cast<uint64_t>(log_idx)) + ",";
        json += "\"removed\":false";
        json += "}";

        for (auto& [id, sub] : subscriptions_) {
            if (sub.type == SubscriptionType::Logs &&
                log_matches_filter(log, sub.log_filter)) {
                sub.pending_events.push_back(SubscriptionEvent{json});
            }
        }
    }
}

void SubscriptionManager::notify_new_pending_transaction(const evmc::bytes32& tx_hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string json = hex_bytes32(tx_hash);

    for (auto& [id, sub] : subscriptions_) {
        if (sub.type == SubscriptionType::NewPendingTransactions) {
            sub.pending_events.push_back(SubscriptionEvent{json});
        }
    }
}

}  // namespace evm_workchain
