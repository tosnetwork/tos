/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "td/utils/Status.h"
#include "td/utils/optional.h"
#include "tos/tos-shard.h"
#include "tos/tos-types.h"
#include "vm/cells.h"

namespace tos_wallet_index {

// Checking imported account history against the authenticated chain.
//
// The retained history window of an index at masterchain block H starts after
// masterchain block B, the last one generated before H's time minus the
// retention period. A transaction is inside the window exactly when its
// shard block was not yet referenced by B, that is when its logical time is
// above the end lt of the shard tip B names for the account's shard. Shards
// advance their logical time independently, so this bound is per shard,
// never one global value.
//
// For an account present in H's state, its last transaction hash and lt are
// authenticated by that state, and every transaction cell names its
// predecessor's hash and lt. A history whose newest row is the state's last
// transaction and whose rows are hash-linked down to a predecessor at or
// below the window bound is therefore exactly the account's in-window
// history. A history that reaches a transaction with no predecessor inside
// the window may belong to a recreated account: deleting an account resets
// its predecessor, so earlier incarnations cannot be reached from the state
// and need the window's blocks to decide.

// The end logical time of one shard tip named by the window's base block B.
struct WindowShardTip {
  tos::ShardIdFull shard;
  uint64_t end_lt = 0;
};

// The window bound for `account` (a basechain address): the end lt of the tip
// whose shard contains it. Exactly one tip must contain it.
td::Result<uint64_t> window_lt_bound(const std::vector<WindowShardTip>& tips, const td::Bits256& account);

// The fields of a transaction cell this check depends on.
struct TransactionLink {
  td::Bits256 account;
  uint64_t lt = 0;
  td::Bits256 prev_hash;
  uint64_t prev_lt = 0;
  uint32_t now = 0;
  td::Bits256 hash;  // the cell's representation hash
};
td::Result<TransactionLink> parse_transaction_link(const td::Ref<vm::Cell>& transaction);

// The account's last transaction as H's state records it.
struct AccountHead {
  uint64_t last_trans_lt = 0;
  td::Bits256 last_trans_hash;
};

enum class LineageVerdict {
  // Every in-window transaction is present and nothing else is: verified.
  Complete,
  // The account is in H's state, its last transaction is before the window
  // and it has no rows: verified.
  OutsideWindow,
  // The rows are authentic, but the history reaches a transaction with no
  // predecessor inside the window, or the account is absent from H's state:
  // completeness needs the window's blocks. Not verified.
  NeedsBlocks,
  // The rows contradict the chain: the import is refused.
  Refused,
};

struct LineageResult {
  LineageVerdict verdict;
  std::string reason;  // set for Refused and NeedsBlocks
};

// Check one account's imported rows, newest first (as the index stores
// them), against its head in H's state (`head` empty when the account is
// absent from H) and the account's window bound. `max_events` is the
// per-account retention cap: a history cut at exactly that many rows is
// complete by retention.
LineageResult verify_account_lineage(const td::Bits256& account, const td::optional<AccountHead>& head,
                                     uint64_t window_bound, const std::vector<td::Ref<vm::Cell>>& rows,
                                     size_t max_events);

}  // namespace tos_wallet_index
