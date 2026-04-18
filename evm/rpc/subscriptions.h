/*
    EVM Workchain — subscription manager for eth_subscribe.

    Manages subscriptions for:
      - newHeads: new block headers
      - logs: new log entries matching a filter
      - newPendingTransactions: new pending transaction hashes

    Each subscription gets a unique ID. Events are queued and retrieved
    via eth_getSubscription (polling) or pushed via WebSocket (future).

    The subscription manager is notified when new blocks/txns/logs
    are produced, and dispatches events to matching subscriptions.

    Source: TOS-specific adapter. Subscription model follows Ethereum spec:
            https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_subscribe
*/
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <evmc/evmc.hpp>
#include <silkworm/core/types/log.hpp>

#include "evm/core/state.h"

namespace evm_workchain {

/// Max queued events per subscription before oldest are dropped.
constexpr size_t kMaxPendingEventsPerSub = 10'000;

enum class SubscriptionType {
    NewHeads,
    Logs,
    NewPendingTransactions,
};

/// A subscription filter for logs (same as eth_newFilter params).
struct LogSubscriptionFilter {
    std::vector<evmc::address> addresses;
    std::vector<std::vector<evmc::bytes32>> topics;
};

/// A queued event for a subscription.
struct SubscriptionEvent {
    std::string json;  // pre-serialised JSON notification payload
};

/// A single subscription.
struct Subscription {
    uint64_t id{0};
    SubscriptionType type;
    LogSubscriptionFilter log_filter;  // only used for Logs type
    std::vector<SubscriptionEvent> pending_events;
};

/// Manages all active subscriptions.
class SubscriptionManager {
  public:
    /// Create a new subscription. Returns the subscription ID.
    uint64_t subscribe(SubscriptionType type,
                       const LogSubscriptionFilter& filter = {});

    /// Remove a subscription. Returns true if it existed.
    bool unsubscribe(uint64_t sub_id);

    /// Get and clear pending events for a subscription.
    std::vector<SubscriptionEvent> poll(uint64_t sub_id);

    /// --- Event producers (called when new data is available) ---

    /// Notify all newHeads subscribers about a new block.
    void notify_new_head(const StoredBlock& block);

    /// Notify matching logs subscribers about new logs.
    void notify_logs(uint64_t block_number, const evmc::bytes32& tx_hash,
                     const std::vector<silkworm::Log>& logs,
                     const evmc::bytes32& block_hash = {});

    /// Notify all newPendingTransactions subscribers about a new tx.
    void notify_new_pending_transaction(const evmc::bytes32& tx_hash);

  private:
    std::mutex mutex_;
    uint64_t next_id_{1};
    std::unordered_map<uint64_t, Subscription> subscriptions_;
};

/// Global subscription manager singleton.
SubscriptionManager& global_subscription_manager();

}  // namespace evm_workchain
