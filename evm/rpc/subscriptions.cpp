/*
    EVM Workchain — subscription manager implementation.
    Source: TOS-specific adapter.
*/
#include "evm/rpc/subscriptions.h"

#include <cstdio>

namespace evm_workchain {

static SubscriptionManager g_sub_manager;

SubscriptionManager& global_subscription_manager() {
    return g_sub_manager;
}

uint64_t SubscriptionManager::subscribe(SubscriptionType type,
                                         const LogSubscriptionFilter& filter) {
    std::lock_guard<std::mutex> lock(mutex_);
    // Security hardening round 6 (R6-H-11): refuse new subscriptions when the global
    // cap is reached. Returning 0 propagates as "too many subscriptions"
    // through the RPC handler. Existing subscriptions are unaffected.
    if (subscriptions_.size() >= kMaxActiveSubscriptions) {
        return 0;
    }
    uint64_t id = next_id_++;
    Subscription sub;
    sub.id = id;
    sub.type = type;
    sub.log_filter = filter;
    subscriptions_[id] = std::move(sub);
    return id;
}

// Round 146 LOW (deferred): subscription IDs are global across
// all clients of the JSON-RPC server.  Any client that knows or
// guesses another client's sub_id can call eth_unsubscribe to
// cancel it, or eth_getSubscription / poll() to drain its
// queued events.  Closing this cleanly requires plumbing a
// per-connection / per-session owner through the JSON-RPC
// dispatch layer (HTTP keep-alive sessions don't carry stable
// identity by default; WS connections do).  Tracked as a
// dedicated follow-up rather than retrofitted with a partial
// guard here.  Mitigating context: sub_ids are 64-bit
// monotonically-incrementing counters, so guessing is bounded
// by the rate at which subscriptions are issued, and the only
// data exposed is what the issuer was already subscribing to —
// there is no privilege escalation, just a cross-client
// availability hazard.  Same shape applies to uno/rpc/
// subscriptions.cpp.
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
    char buf[46];  // "0x" + 40 hex + quote + quote + null = 45
    snprintf(buf, sizeof(buf), "\"0x");
    for (int i = 0; i < 20; i++) snprintf(buf + 3 + i*2, 3, "%02x", addr.bytes[i]);
    buf[43] = '"';
    buf[44] = '\0';
    return buf;
}

static std::string hex_bytes32(const evmc::bytes32& h) {
    char buf[70];  // "0x" + 64 hex + quote + quote + null = 69
    snprintf(buf, sizeof(buf), "\"0x");
    for (int i = 0; i < 32; i++) snprintf(buf + 3 + i*2, 3, "%02x", h.bytes[i]);
    buf[67] = '"';
    buf[68] = '\0';
    return buf;
}

static std::string hex_u64(uint64_t v) {
    char buf[32];
    if (v == 0) return "\"0x0\"";
    snprintf(buf, sizeof(buf), "\"0x%llx\"", (unsigned long long)v);
    return buf;
}

// Cap pending events per subscription (drop oldest if over limit).
static void cap_events(Subscription& sub) {
    if (sub.pending_events.size() > kMaxPendingEventsPerSub) {
        sub.pending_events.erase(
            sub.pending_events.begin(),
            sub.pending_events.begin() +
                static_cast<ptrdiff_t>(sub.pending_events.size() - kMaxPendingEventsPerSub));
    }
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
            cap_events(sub);
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
                                       const std::vector<silkworm::Log>& logs,
                                       const evmc::bytes32& block_hash) {
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
        json += "\"transactionIndex\":\"0x0\",";
        json += "\"blockHash\":" + hex_bytes32(block_hash) + ",";
        json += "\"removed\":false";
        json += "}";

        for (auto& [id, sub] : subscriptions_) {
            if (sub.type == SubscriptionType::Logs &&
                log_matches_filter(log, sub.log_filter)) {
                sub.pending_events.push_back(SubscriptionEvent{json});
                cap_events(sub);
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
            cap_events(sub);
        }
    }
}

}  // namespace evm_workchain
