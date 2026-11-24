#include "block/settlement-assets.h"
#include "vm/cells/CellSlice.h"
#include "vm/dict.h"
#include "vm/excno.hpp"

namespace block {
namespace {
constexpr unsigned long long kAssetsTag = 0x01;
constexpr unsigned long long kAssetTag = 0x01;
// kind:uint8 bridge_address:bits256 source_chain_id:uint32 source_token:bits160
constexpr unsigned kOriginBits = 8 + 256 + 32 + 160;

td::Status invalid(const char* why) {
  return td::Status::Error(PSLICE() << "invalid recognized settlement assets (ConfigParam 84): " << why);
}

// An ordinary cell, as every value of this parameter must be.
bool ordinary_slice(const td::Ref<vm::Cell>& cell, vm::CellSlice& out) {
  if (cell.is_null() || cell->get_level() != 0) {
    return false;
  }
  bool special = false;
  out = vm::load_cell_slice_special(cell, special);
  return !special;
}

// Coins in its shortest encoding: len:(#< 16) value:(uint (len * 8)), with a
// non-zero top byte. Zero (len 0) is refused by the caller.
td::Result<td::RefInt256> fetch_canonical_coins(vm::CellSlice& cs) {
  unsigned long long len = 0;
  if (!cs.fetch_ulong_bool(4, len)) {
    return invalid("truncated max_liability_per_actor");
  }
  if (len == 0) {
    return invalid("max_liability_per_actor is zero");
  }
  if (cs.size() < len * 8) {
    return invalid("truncated max_liability_per_actor");
  }
  if (cs.prefetch_ulong(8) == 0) {
    return invalid("max_liability_per_actor is not in its shortest encoding");
  }
  // A non-zero length with a non-zero top byte is a positive amount.
  auto value = cs.fetch_int256(static_cast<unsigned>(len * 8), false);
  if (value.is_null()) {
    return invalid("truncated max_liability_per_actor");
  }
  return value;
}

td::Result<SettlementAssetOrigin> unpack_origin(td::Ref<vm::Cell> cell) {
  vm::CellSlice cs;
  if (!ordinary_slice(cell, cs)) {
    return invalid("origin is not an ordinary cell");
  }
  if (cs.size() != kOriginBits || cs.size_refs() != 0) {
    return invalid("origin has the wrong size");
  }
  SettlementAssetOrigin origin;
  auto kind = cs.fetch_ulong(8);
  if (kind != static_cast<unsigned>(SettlementAssetOriginKind::TokenBridge) &&
      kind != static_cast<unsigned>(SettlementAssetOriginKind::NativeIssuance)) {
    return invalid("unknown origin kind");
  }
  origin.kind = static_cast<SettlementAssetOriginKind>(kind);
  if (!cs.fetch_bits_to(origin.bridge_address)) {
    return invalid("truncated origin");
  }
  origin.source_chain_id = static_cast<td::uint32>(cs.fetch_ulong(32));
  if (!cs.fetch_bits_to(origin.source_token)) {
    return invalid("truncated origin");
  }
  return origin;
}

td::Result<SettlementAsset> unpack_asset(vm::CellSlice cs, td::ConstBitPtr key) {
  SettlementAsset asset;
  asset.master = td::Bits256{key};
  if (cs.fetch_ulong(8) != kAssetTag) {
    return invalid("unknown record tag");
  }
  auto status = cs.fetch_ulong(8);
  if (status < static_cast<unsigned>(SettlementAssetStatus::Active) ||
      status > static_cast<unsigned>(SettlementAssetStatus::Retired)) {
    return invalid("unknown status");
  }
  asset.status = static_cast<SettlementAssetStatus>(status);
  auto decimals = cs.fetch_ulong(8);
  if (decimals > 0xff) {
    return invalid("truncated record");
  }
  asset.decimals = static_cast<td::uint8>(decimals);
  if (!cs.fetch_bits_to(asset.minter_code_hash) || !cs.fetch_bits_to(asset.wallet_code_hash)) {
    return invalid("truncated record");
  }
  TRY_RESULT_ASSIGN(asset.max_liability_per_actor, fetch_canonical_coins(cs));
  if (cs.size() != 0 || cs.size_refs() != 1) {
    return invalid("record carries trailing data");
  }
  TRY_RESULT_ASSIGN(asset.origin, unpack_origin(cs.fetch_ref()));
  return asset;
}
}  // namespace

bool SettlementAsset::uncapped() const {
  static const td::RefInt256 largest = (td::make_refint(1) << 120) - 1;
  return max_liability_per_actor.not_null() && td::cmp(max_liability_per_actor, largest) == 0;
}

td::Result<std::vector<SettlementAsset>> unpack_settlement_assets(td::Ref<vm::Cell> value) {
  try {
    vm::CellSlice cs;
    if (!ordinary_slice(value, cs)) {
      return invalid("not an ordinary cell");
    }
    if (cs.fetch_ulong(8) != kAssetsTag) {
      return invalid("unknown tag");
    }
    td::Ref<vm::Cell> root;
    if (!cs.fetch_maybe_ref(root) || !cs.empty_ext()) {
      return invalid("value carries trailing data");
    }
    std::vector<SettlementAsset> assets;
    if (root.is_null()) {
      return assets;
    }
    td::Status failure = td::Status::OK();
    vm::Dictionary dict{root, 256};
    bool complete = dict.check_for_each([&](td::Ref<vm::CellSlice> entry, td::ConstBitPtr key, int bits) {
      if (bits != 256 || entry.is_null()) {
        failure = invalid("malformed dictionary");
        return false;
      }
      auto asset = unpack_asset(*entry, key);
      if (asset.is_error()) {
        failure = asset.move_as_error();
        return false;
      }
      assets.push_back(asset.move_as_ok());
      return true;
    });
    if (failure.is_error()) {
      return std::move(failure);
    }
    if (!complete) {
      return invalid("malformed dictionary");
    }
    return assets;
  } catch (vm::VmError&) {
    return invalid("malformed cell");
  } catch (vm::VmVirtError&) {
    return invalid("malformed cell");
  }
}

}  // namespace block
