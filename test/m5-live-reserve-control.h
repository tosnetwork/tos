#pragma once
// Actual registered engine/configuration-admission hook, not a detached fee
// arithmetic oracle. This deliberately stops before cryptographic verification.
#include "m3-live-wallet.h"

namespace m3_live {
inline void check_m5_reserve_admission(const std::filesystem::path& fixture, int selected_direction = 0) {
  CHECK(selected_direction >= -1 && selected_direction <= 1);
  auto root = load(fixture / "zerostate.boc");
  tos::BlockIdExt zero{tos::BlockId{tos::masterchainId, tos::shardIdAll, 0},
      root->get_hash().bits(), td::Bits256::zero()};
  auto config = block::ConfigInfo::extract_config(root, zero,
      block::Config::needWorkchainInfo | block::Config::needCapabilities).move_as_ok();
  block::WorkchainExecutionRegistry registry;
  registry.register_account_engine(std::make_unique<block::m3_test::M3NodeEngine>(
      block::WorkchainEngineKey{block::WorkchainFormat::Basic, 0x434e5431},
      (fixture / "reserve-control.calls").string())).ensure();
  auto resolved = registry.resolve_scoped_workchain(2, *config).move_as_ok();
  CHECK(resolved && std::holds_alternative<block::ResolvedWorkchainAccountBinding>(*resolved));
  const auto& binding = std::get<block::ResolvedWorkchainAccountBinding>(*resolved);
  auto candidate = load(fixture / "operation.candidate.boc");
  auto input = block::m3_test::decode_m5_test_debit(candidate).move_as_ok();
  auto probe = [&](const auto& value) {
    return binding.executor->proof_work(value, binding.input_policy.identity(), *binding.engine_config);
  };
  auto unchanged = probe(candidate);
  if (unchanged.is_error()) std::cerr << "D76_RESERVE_POSITIVE " << unchanged.error().to_string() << std::endl;
  CHECK(unchanged.is_ok());
  for (int direction : {-1, 1}) {
    if (selected_direction && selected_direction != direction) continue;
    auto changed = input;
    auto& reserve = changed.data.amounts.return_reserve;
    CHECK(direction < 0 ? !__builtin_sub_overflow(reserve, std::uint64_t{1}, &reserve)
                        : !__builtin_add_overflow(reserve, std::uint64_t{1}, &reserve));
    auto wire = block::m3_test::wrap_m5_test_debit(block::encode_workchain_withdrawal_input(changed).move_as_ok());
    auto result = probe(wire);
    std::cout << "D76_RESERVE_PROBE direction=" << direction << " declared=" << reserve
              << " accepted=" << input.data.amounts.return_reserve << std::endl;
    if (result.is_error()) std::cout << "D76_RESERVE_STATUS " << result.error().to_string() << std::endl;
    CHECK(result.is_error());
    CHECK(result.error().code() == -7200);
    CHECK(result.error().message() == "Withdrawal reserve differs from authenticated max_bounce_cost");
    std::cout << "D76_RESERVE_ADMISSION direction=" << direction << " declared=" << reserve
              << ": -7200 at authenticated reserve equality\n";
  }
}
} // namespace m3_live
