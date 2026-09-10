#pragma once
// TEST wallet input acquisition. Authorization files are proposer inputs only;
// they are never passed to validator replay, which consumes serialized blocks.
#include "block/workchain-registration.h"
#include "block/workchain-account-access-codec.h"
#include "crypto/test/workchain-m3-registration-wallet.h"
#include "crypto/test/workchain-m3-business-config.h"
#include <fstream>

namespace m3_live {
inline td::Ref<vm::Cell> load(const std::filesystem::path& path) {
  return vm::std_boc_deserialize(td::read_file_str(path.string()).move_as_ok()).move_as_ok();
}
inline void save(const std::filesystem::path& path, td::Ref<vm::Cell> root) {
  td::write_file(path.string(), vm::std_boc_serialize(root, 31).move_as_ok()).ensure();
}
inline std::string field(const std::filesystem::path& path, const std::string& key) {
  std::ifstream stream(path);
  CHECK(stream.good());
  std::string line, answer;
  bool found = false;
  while (std::getline(stream, line)) {
    if (line.starts_with(key + "=")) {
      CHECK(!found);
      found = true;
      answer = line.substr(key.size() + 1);
    }
  }
  CHECK(found);
  return answer;
}
inline void registration_request(const std::filesystem::path& fixture, unsigned owner = 0) {
  using namespace block;
  auto root = load(fixture / "zerostate.boc");
  tos::BlockIdExt zero{tos::BlockId{tos::masterchainId, tos::shardIdAll, 0},
                      root->get_hash().bits(), td::Bits256::zero()};
  auto config = ConfigInfo::extract_config(root, zero,
      Config::needWorkchainInfo | Config::needCapabilities).move_as_ok();
  const auto ingress = load_workchain_native_ingress_table(*config).move_as_ok().at(2);
  auto p = decode_workchain_engine_parameters(ingress.engine_configuration).move_as_ok();
  auto b = m3_test::decode_m3_test_business_parameters(p.parameters).move_as_ok();
  WorkchainPossessionPolicy possession{
      {2, 1, 1, 2, config->get_global_blockchain_id(), 2, root->get_hash().bits(), p.instance_id},
      b.rules, {config->get_root_cell()->get_hash().bits(), b.generator_profile, b.range_profile},
      b.fee_profile, b.fee_effective_height};
  WorkchainRegistrationPolicy policy{config->get_global_blockchain_id(), root->get_hash().bits(), p.instance_id,
      {b.rules.asset, b.rules.custody, b.rules.policy}, b.account_schema, b.relation_profile, b.proof_profile,
      p.registration_deposit, possession, config->get_workchain_list()};
  td::Bits256 payer = td::Bits256::zero(), account = td::Bits256::zero(), public_key;
  payer.as_slice()[31] = 1;
  CHECK(owner < 2);
  account.as_slice().fill(owner == 0 ? 0x11 : 0x22);
  auto key = td::hex_decode(field(fixture / "wallet-key.txt", "public_key")).move_as_ok();
  CHECK(key.size() == 32);
  public_key.as_slice().copy_from(key);
  auto input = m3_test::make_m3_test_registration_wallet_input(policy, 0, payer, public_key, account).move_as_ok();
  save(fixture / "registration-0.account.boc", input.account_data);
  save(fixture / "registration-0.unsigned.boc", encode_workchain_replay_input(
      WorkchainRegistrationReplayInput{input.operation_id, input.context, {}}).move_as_ok());
  td::write_file((fixture / "registration-0.request.txt").string(),
      std::string(owner == 0 ? "secret=101\ncontext=" : "secret=223\ncontext=") + td::hex_encode(input.context_bytes) +
      "\nprefix=" + td::hex_encode(input.prefix_bytes) + "\n").ensure();
}
inline void registration_finish(const std::filesystem::path& fixture) {
  using namespace block;
  auto data = load(fixture / "registration-0.account.boc");
  auto account = decode_workchain_confidential_account(data).move_as_ok();
  auto unsigned_input = decode_workchain_replay_input(load(fixture / "registration-0.unsigned.boc")).move_as_ok();
  CHECK(std::holds_alternative<WorkchainRegistrationReplayInput>(unsigned_input));
  auto signed_input = std::get<WorkchainRegistrationReplayInput>(unsigned_input);
  auto bytes = td::hex_decode(field(fixture / "registration-0.proof.txt", "proof")).move_as_ok();
  CHECK(bytes.size() == 64);
  std::copy(bytes.begin(), bytes.end(), signed_input.proof.begin());
  save(fixture / "registration-0.candidate.boc", encode_workchain_replay_input(signed_input).move_as_ok());
  auto old = load(fixture / "current-state.boc");
  gen::ShardStateUnsplit::Record state;
  CHECK(::tlb::unpack_cell(old, state));
  const auto coordinator = td::Bits256::zero();
  vm::AugmentedDictionary dictionary(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  Account native(2, coordinator.bits());
  CHECK(native.unpack(dictionary.lookup(coordinator), state.gen_utime, false));
  WorkchainAccountDeclarations declarations{
      {{coordinator, td::Bits256(native.total_state->get_hash().bits())}, {account.address.account, std::nullopt}},
      {coordinator, account.address.account}};
  save(fixture / "registration-0.declarations.boc", encode_workchain_account_declarations(declarations, 3, 3).move_as_ok());
  // Source is addr_none: ordinary wc=0 action processing supplies the real payer,
  // creation LT, timestamp and forwarding fees. This is not a forged final import.
  vm::CellBuilder internal;
  internal.store_long(6, 4).store_long(0, 2).store_long(4, 3).store_long(2, 8)
      .store_bits(coordinator.bits(), 256);
  auto amount = vm::CellBuilder().store_long(account.funding.paid_deposit, 64).finalize();
  CHECK(CurrencyCollection(vm::load_cell_slice(amount).fetch_int256(64, false)).store(internal));
  internal.store_long(0, 4).store_long(0, 4).store_long(0, 64).store_long(0, 32)
      .store_long(0, 1).store_long(1, 1).store_ref(data);
  vm::CellBuilder external;
  external.store_long(2, 2).store_long(0, 2).store_long(4, 3).store_long(0, 8)
      .store_bits(account.funding.refund_account.bits(), 256).store_long(0, 4)
      .store_long(0, 1).store_long(0, 1).store_ref(internal.finalize());
  save(fixture / "registration-0.message.boc", external.finalize());
}
}  // namespace m3_live
