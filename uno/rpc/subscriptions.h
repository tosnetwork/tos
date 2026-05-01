/*
    Uno Workchain — optional pub/sub for included-tx notifications.

    Mirrors `evm/rpc/subscriptions.h` (eth_subscribe / eth_unsubscribe) but
    exposes only the event classes that are meaningful on a shielded
    note-pool workchain:

      - includedTx         : fires once per Transfer that is accepted into a
                             block; payload is { tx_hash, block_seqno, fee }
                             (NO amounts, NO note metadata — the chain never
                             knows those).
      - newHead            : fires once per wc=2 block; payload is
                             { seqno, anchor_root, tx_count, note_count }.
      - newAnchor          : duplicate-but-explicit channel mirroring
                             `uno_getAnchor`'s head changes; convenience for
                             wallets picking an anchor for the next tx.

    We deliberately do NOT expose subscriptions tied to per-wallet state
    (cf. the `logs` filter on eth_subscribe) — that would require the
    server to know wallet identity, violating §5.6's "no accounts on chain"
    invariant. Wallets scan blocks locally via uno_getBlockFilter.
*/
#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace uno_workchain {

/// Max queued events per subscription before oldest are dropped.
/// Matches the EVM subscription manager's cap.
constexpr size_t kMaxPendingEventsPerUnoSub = 10'000;

/// Security hardening round 6 (R6-H-11): hard cap on the total number of active
/// Uno subscriptions across all callers, mirroring the EVM cap. Without
/// this, public RPC clients can accumulate subscription IDs without
/// bound — every notify_* call iterates the full subscription map and
/// appends events under the manager mutex, so attacker-created state
/// scales publisher CPU/memory linearly. 4096 mirrors the EVM cap.
constexpr size_t kMaxActiveUnoSubscriptions = 4096;

enum class UnoSubscriptionType {
    IncludedTx,
    NewHead,
    NewAnchor,
};

struct UnoSubscriptionEvent {
    std::string json;  // pre-serialised JSON notification payload
};

struct UnoSubscription {
    uint64_t            id{0};
    UnoSubscriptionType type;
    std::vector<UnoSubscriptionEvent> pending_events;
};

class UnoSubscriptionManager {
  public:
    /// Create a new subscription. Returns the subscription ID.
    uint64_t subscribe(UnoSubscriptionType type);

    /// Remove a subscription. Returns true if it existed.
    bool unsubscribe(uint64_t sub_id);

    /// Drain and return queued events.
    std::vector<UnoSubscriptionEvent> poll(uint64_t sub_id);

    // --- Event producers. Called by the end-of-block hook and the compute
    //     phase after verify_transfer → apply_transfer succeeds.

    /// One Transfer was accepted into a block.
    /// @param tx_hash_hex  64-char lowercase hex of the 32-byte BLAKE3 hash.
    /// @param block_seqno  The block it was applied to.
    /// @param fee_nano     Public fee paid (§4.1), in nano-UNO units.
    void notify_included_tx(const std::string& tx_hash_hex,
                            uint64_t           block_seqno,
                            uint64_t           fee_nano);

    /// One wc=2 block committed.
    void notify_new_head(uint64_t           block_seqno,
                         const std::string& anchor_root_hex,
                         uint64_t           tx_count,
                         uint64_t           note_count);

    /// Explicit anchor-channel push (usually same seqno as newHead).
    void notify_new_anchor(uint64_t           block_seqno,
                           const std::string& anchor_root_hex);

    /// Test helper: drop all subscriptions + events.
    void reset_for_test();

  private:
    std::mutex mutex_;
    uint64_t   next_id_{1};
    std::unordered_map<uint64_t, UnoSubscription> subscriptions_;
};

/// Global subscription manager singleton.
UnoSubscriptionManager& global_uno_subscription_manager();

}  // namespace uno_workchain
