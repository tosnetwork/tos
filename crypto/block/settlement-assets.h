#pragma once

#include <vector>

#include "common/refint.h"
#include "td/utils/Status.h"
#include "td/utils/bits.h"
#include "td/utils/int_types.h"
#include "vm/cells.h"

namespace block {

// ConfigParam 84: the recognized settlement assets (block.tlb SettlementAssets).
inline constexpr int settlement_assets_config_param = 84;

enum class SettlementAssetStatus : td::uint8 { Active = 1, AdmissionSuspended = 2, Retired = 3 };
enum class SettlementAssetOriginKind : td::uint8 { TokenBridge = 1, NativeIssuance = 2 };

struct SettlementAssetOrigin {
  SettlementAssetOriginKind kind = SettlementAssetOriginKind::TokenBridge;
  td::Bits256 bridge_address;
  td::uint32 source_chain_id = 0;
  td::BitArray<160> source_token;
};

struct SettlementAsset {
  // Account id of the token master on workchain 0 (the dictionary key).
  td::Bits256 master;
  SettlementAssetStatus status = SettlementAssetStatus::Active;
  td::uint8 decimals = 0;
  td::Bits256 minter_code_hash;
  td::Bits256 wallet_code_hash;
  // Non-zero; the largest Coins value (2^120 - 1) means no cap.
  td::RefInt256 max_liability_per_actor;
  SettlementAssetOrigin origin;

  bool uncapped() const;
};

// Decodes a ConfigParam 84 value exactly: both constructor tags, the status and
// origin kinds the schema defines, a non-zero liability cap in its shortest
// Coins encoding, and no trailing bits or references in any record. Entries
// come back in ascending key order. Any deviation refuses the whole value.
td::Result<std::vector<SettlementAsset>> unpack_settlement_assets(td::Ref<vm::Cell> value);

}  // namespace block
