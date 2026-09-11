#pragma once
// Shape NOT frozen. Test-scope only.
// The production business-config codec is a separate, undecided unit;
// do not treat this layout as a precedent. Never install a production parser
// or deployment-config hook for this test fixture representation.

#include "block/workchain-confidential-input.h"
#include "block/workchain-deposit-admission.h"
#include "block/workchain-operation-fees.h"
#include "uno/crypto/include/uno_crypto.h"
#include <array>
#include <utility>

namespace block::m3_test {
struct M3TestBusinessParameters {
  UnoCryptoLimits limits;
  std::array<unsigned char, 80> domain;
  std::uint64_t send_fee, collect_fee;
  gen::UnoV2TransferRulesV1::Record rules;
  td::Bits256 generator_profile, range_profile, fee_profile;
  std::uint32_t fee_effective_height;
  std::uint16_t account_schema, relation_profile, proof_profile;
  // Absence represents the old M3-only layout, NEVER a Deposit default.
  // Version 2 carries all four additional fields; maximum comes from limits.
  std::optional<WorkchainDepositPolicy> deposit;
  // Version 3: explicit static C unit price and operation-specific T. S is the
  // authenticated Deposit slot price for SEND and zero for COLLECT (D25).
  // Legacy aggregate send_fee/collect_fee must be zero reserved fields here;
  // they are not split, inferred, or used as a fallback for missing components.
  std::optional<WorkchainStaticOperationTariff> operation_tariff;

  M3TestBusinessParameters() = delete;
  M3TestBusinessParameters(UnoCryptoLimits limits_value, std::array<unsigned char, 80> domain_value,
      std::uint64_t send, std::uint64_t collect, gen::UnoV2TransferRulesV1::Record rules_value,
      td::Bits256 generator, td::Bits256 range, td::Bits256 fee, std::uint32_t effective_height,
      std::uint16_t schema, std::uint16_t relation, std::uint16_t proof)
      : limits(limits_value), domain(domain_value), send_fee(send), collect_fee(collect),
        rules(std::move(rules_value)), generator_profile(generator), range_profile(range), fee_profile(fee),
        fee_effective_height(effective_height), account_schema(schema), relation_profile(relation), proof_profile(proof) {}
};

namespace business_config_detail {
constexpr std::uint32_t tag = 0x4d335443;  // M3TC: explicitly TEST, not a frozen production tag.
constexpr std::uint16_t version = 1;
inline td::Status malformed() { return td::Status::Error("malformed M3 test business parameters"); }
inline td::Result<vm::CellSlice> exact(const td::Ref<vm::Cell>& cell, unsigned bits, unsigned refs) {
  if (cell.is_null()) return malformed();
  bool special = false;
  auto slice = vm::load_cell_slice_special(cell, special);
  if (special || slice.size() != bits || slice.size_refs() != refs) return malformed();
  return slice;
}
}  // namespace business_config_detail

// No protocol/network/current-height values and no configuration hash here.
// The host derives configuration identity from the authenticated enclosing
// configuration; including its hash inside these parameters would be circular.
// Exact representation only: semantic policy validation/binding is the host's
// responsibility. Codec errors carry no candidate/local verdict; acquisition
// exceptions propagate so that the host can classify by authenticated source.
inline td::Result<td::Ref<vm::Cell>> encode_m3_test_business_parameters(const M3TestBusinessParameters& value) {
  using namespace business_config_detail;
  if (!std::in_range<std::uint64_t>(value.limits.max_collect) ||
      !std::in_range<std::uint64_t>(value.limits.max_context_bytes) ||
      !std::in_range<std::uint64_t>(value.limits.max_proof_bytes))
    return td::Status::Error("M3 test limit cannot fit uint64 wire field");
  vm::CellBuilder limits, domain, profiles, root;
  if (!limits.store_long_bool(value.limits.max_balance, 64) ||
      !limits.store_long_bool(value.limits.max_value, 64) ||
      !limits.store_long_bool(static_cast<std::uint64_t>(value.limits.max_collect), 64) ||
      !limits.store_long_bool(static_cast<std::uint64_t>(value.limits.max_context_bytes), 64) ||
      !limits.store_long_bool(static_cast<std::uint64_t>(value.limits.max_proof_bytes), 64) ||
      !domain.store_bytes_bool(td::Slice(value.domain.data(), value.domain.size())) ||
      !profiles.store_bits_bool(value.generator_profile.bits(), 256) ||
      !profiles.store_bits_bool(value.range_profile.bits(), 256) ||
      !profiles.store_bits_bool(value.fee_profile.bits(), 256)) return malformed();
  TRY_RESULT(rules, confidential_input_detail::pack(value.rules));
  if (value.deposit && value.deposit->maximum != value.limits.max_value)
    return td::Status::Error("Deposit maximum differs from authenticated kernel limit");
  if (value.operation_tariff && (!value.deposit || value.send_fee || value.collect_fee || value.proof_profile != 4))
    return td::Status::Error("component tariff requires Deposit policy, profile 4 and zero legacy fee fields");
  if (!root.store_long_bool(tag, 32) || !root.store_long_bool(value.operation_tariff ? 3 : value.deposit ? 2 : version, 16) ||
      !root.store_long_bool(value.send_fee, 64) || !root.store_long_bool(value.collect_fee, 64) ||
      !root.store_long_bool(value.fee_effective_height, 32) || !root.store_long_bool(value.account_schema, 16) ||
      !root.store_long_bool(value.relation_profile, 16) || !root.store_long_bool(value.proof_profile, 16) ||
      !root.store_ref_bool(limits.finalize()) || !root.store_ref_bool(domain.finalize()) ||
      !root.store_ref_bool(rules) || !root.store_ref_bool(profiles.finalize())) return malformed();
  if (value.deposit && (!root.store_long_bool(value.deposit->minimum, 64) ||
      !root.store_long_bool(value.deposit->slot_fee, 64) ||
      !root.store_long_bool(value.deposit->user_slots, 32) ||
      !root.store_long_bool(value.deposit->system_slots, 32))) return malformed();
  if (value.operation_tariff && (!root.store_long_bool(value.operation_tariff->base, 64) ||
      !root.store_long_bool(value.operation_tariff->send_tip, 64) ||
      !root.store_long_bool(value.operation_tariff->collect_tip, 64))) return malformed();
  return td::Ref<vm::Cell>{root.finalize()};
}

inline td::Result<M3TestBusinessParameters> decode_m3_test_business_parameters(const td::Ref<vm::Cell>& cell) {
  using namespace business_config_detail;
  if (cell.is_null()) return malformed();
  bool special = false;
  auto root = vm::load_cell_slice_special(cell, special);
  if (special || root.size_refs() != 4 || (root.size() != 256 && root.size() != 448 && root.size() != 640)) return malformed();
  if (root.fetch_ulong(32) != tag) return td::Status::Error("unknown M3 test business tag");
  auto wire_version = root.fetch_ulong(16);
  if (wire_version != version && wire_version != 2 && wire_version != 3)
    return td::Status::Error("unsupported M3 test business version");
  if (root.size() != (wire_version == 3 ? 592u : wire_version == 2 ? 400u : 208u)) return malformed();
  const auto send = root.fetch_ulong(64), collect = root.fetch_ulong(64);
  const auto height = static_cast<std::uint32_t>(root.fetch_ulong(32));
  const auto schema = static_cast<std::uint16_t>(root.fetch_ulong(16));
  const auto relation = static_cast<std::uint16_t>(root.fetch_ulong(16));
  const auto proof = static_cast<std::uint16_t>(root.fetch_ulong(16));
  TRY_RESULT(limits, exact(root.fetch_ref(), 320, 0));
  TRY_RESULT(domain, exact(root.fetch_ref(), 640, 0));
  auto rules_root = root.fetch_ref();
  TRY_RESULT(rules_shape, exact(rules_root, 800, 0));
  (void)rules_shape;
  TRY_RESULT(rules, confidential_input_detail::unpack<gen::UnoV2TransferRulesV1::Record>(rules_root));
  TRY_RESULT(profiles, exact(root.fetch_ref(), 768, 0));
  const auto max_balance = limits.fetch_ulong(64), max_value = limits.fetch_ulong(64);
  const auto max_collect = limits.fetch_ulong(64), max_context = limits.fetch_ulong(64), max_proof = limits.fetch_ulong(64);
  if (!std::in_range<std::size_t>(max_collect) || !std::in_range<std::size_t>(max_context) ||
      !std::in_range<std::size_t>(max_proof)) return td::Status::Error("M3 test limit cannot fit host size_t");
  std::array<unsigned char, 80> domain_bytes;
  td::Bits256 generator, range, fee;
  if (!domain.fetch_bytes(td::MutableSlice(domain_bytes.data(), domain_bytes.size())) ||
      !profiles.fetch_bits_to(generator) || !profiles.fetch_bits_to(range) || !profiles.fetch_bits_to(fee))
    return malformed();
  M3TestBusinessParameters result{{max_balance, max_value, static_cast<std::size_t>(max_collect),
      static_cast<std::size_t>(max_context), static_cast<std::size_t>(max_proof)}, domain_bytes, send, collect,
      rules, generator, range, fee, height, schema, relation, proof};
  if (wire_version >= 2) {
    auto minimum = root.fetch_ulong(64), slot_fee = root.fetch_ulong(64);
    auto user_slots = static_cast<std::uint32_t>(root.fetch_ulong(32));
    auto system_slots = static_cast<std::uint32_t>(root.fetch_ulong(32));
    result.deposit = WorkchainDepositPolicy{minimum, max_value, slot_fee, user_slots, system_slots};
  }
  if (wire_version == 3) {
    if (send || collect || proof != 4) return td::Status::Error("component tariff has incompatible legacy fee fields or profile");
    const auto base = root.fetch_ulong(64), send_tip = root.fetch_ulong(64), collect_tip = root.fetch_ulong(64);
    result.operation_tariff = WorkchainStaticOperationTariff{base, send_tip, collect_tip};
  }
  return result;
}

inline td::Result<WorkchainDepositPolicy> require_m4_deposit_policy(const M3TestBusinessParameters& parameters) {
  if (!parameters.deposit) return td::Status::Error(-7201, "authenticated Deposit parameters absent");
  return *parameters.deposit;
}
inline td::Result<WorkchainStaticOperationTariff> require_m4_operation_tariff(const M3TestBusinessParameters& parameters) {
  if (!parameters.operation_tariff || !parameters.deposit)
    return td::Status::Error(-7201, "authenticated operation fee components absent");
  return *parameters.operation_tariff;
}
}  // namespace block::m3_test
