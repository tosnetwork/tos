/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <string>

#include "td/utils/Slice.h"
#include "td/utils/Status.h"

namespace tos::proofverify {

constexpr std::size_t kMaxWalletTransactionBytes = 1u << 20;
constexpr int kMaxWalletTransactionCells = 16384;
constexpr int kMaxWalletTransactionDepth = 1023;
constexpr int kMaxWalletTransactionMessages = 256;
constexpr std::size_t kMaxWalletTransactionResultBytes = 1u << 20;

// Pure bounded codec/hash verification. The caller obtains the account/hash/lt
// from a separately authenticated ShardAccount, not from transaction RPC JSON.
td::Result<std::string> verify_wallet_transaction(td::Slice account_hash, td::uint64 logical_time,
                                                td::Slice transaction_hash, td::Slice boc);

}  // namespace tos::proofverify
