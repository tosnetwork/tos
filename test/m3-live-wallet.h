#pragma once
// TEST wallet requests use the actual issued configuration and accepted state.
// This is not a production business-config codec or a deployment wallet.
#include "m3-live-state.h"
#include "block/workchain-confidential-execution.h"
#include "crypto/test/workchain-m3-wallet-requests.h"
#include "crypto/test/workchain-m3-closure-wallet.h"
#include "crypto/test/workchain-m4-wallet-receipts.h"
#include "crypto/test/workchain-m5-debit.h"
#include "crypto/test/workchain-m5-payout.h"

namespace m3_live {
inline std::optional<std::uint32_t> m5_live_withdrawal_limit(const std::filesystem::path& fixture) {
  auto root = load(fixture / "zerostate.boc");
  tos::BlockIdExt zero{tos::BlockId{tos::masterchainId,tos::shardIdAll,0},root->get_hash().bits(),td::Bits256::zero()};
  auto config = block::ConfigInfo::extract_config(root,zero,block::Config::needWorkchainInfo | block::Config::needCapabilities).move_as_ok();
  auto ingress = block::load_workchain_native_ingress_table(*config).move_as_ok().at(2);
  auto business = block::m3_test::decode_m3_test_business_parameters(
      block::decode_workchain_engine_parameters(ingress.engine_configuration).move_as_ok().parameters).move_as_ok();
  if (!business.prepare) return {};
  return business.prepare->withdrawal_limit;
}
inline block::WorkchainWithdrawalAccount m5_live_account(const td::Ref<vm::Cell>& root,
                                                        std::optional<std::uint32_t> limit) {
  auto slice = vm::load_cell_slice(root);
  if (slice.prefetch_ulong(32) == block::gen::UnoV2AccountStateWithdrawalsV2::cons_tag[0]) {
    CHECK(limit);
    return block::decode_workchain_withdrawal_account(root,*limit).move_as_ok();
  }
  auto account = block::decode_workchain_confidential_account(root).move_as_ok();
  return {account,{account.lifecycle,{}},{}};
}
inline td::Bits256 wallet_account(unsigned owner) {
  CHECK(owner < 2);
  td::Bits256 result;
  result.as_slice().fill(owner == 0 ? 0x11 : 0x22);
  return result;
}
inline block::WorkchainTransferEnvironment wallet_environment(const std::filesystem::path& fixture, unsigned kind) {
  CHECK(kind == 1 || kind == 2);
  auto root = load(fixture / "zerostate.boc");
  tos::BlockIdExt zero{tos::BlockId{tos::masterchainId, tos::shardIdAll, 0},
                      root->get_hash().bits(), td::Bits256::zero()};
  auto config = block::ConfigInfo::extract_config(root, zero,
      block::Config::needWorkchainInfo | block::Config::needCapabilities).move_as_ok();
  const auto ingress = block::load_workchain_native_ingress_table(*config).move_as_ok().at(2);
  const auto parameters = block::decode_workchain_engine_parameters(ingress.engine_configuration).move_as_ok();
  const auto b = block::m3_test::decode_m3_test_business_parameters(parameters.parameters).move_as_ok();
  block::gen::ShardStateUnsplit::Record previous;
  CHECK(tlb::unpack_cell(load(fixture / "current-state.boc"), previous));
  CHECK(previous.seq_no < UINT32_MAX);
  auto fee = kind == 1 ? b.send_fee : b.collect_fee;
  if (b.deposit) {
    CHECK(b.operation_tariff);
    fee = block::derive_workchain_operation_fee_amounts(*b.operation_tariff, b.deposit->slot_fee, kind).move_as_ok().total;
  }
  return {b.limits, b.domain,
      {2, 1, 1, 2, kind, config->get_global_blockchain_id(), 2, root->get_hash().bits(), parameters.instance_id},
      b.rules, {config->get_root_cell()->get_hash().bits(), b.generator_profile, b.range_profile},
      b.fee_profile, b.fee_effective_height, previous.seq_no + 1,
      fee, 16, b.account_schema, b.relation_profile, b.proof_profile};
}
inline block::WorkchainConfidentialAccount wallet_state(const std::filesystem::path& fixture, unsigned owner) {
  return block::decode_workchain_confidential_account(
      account_data(load(fixture / "current-state.boc"), wallet_account(owner))).move_as_ok();
}
inline void save_operation(const std::filesystem::path& fixture, td::Ref<vm::Cell> candidate,
                           std::vector<td::Bits256> accounts) {
  accounts.push_back(td::Bits256::zero());  // Actual coordinator entry participant.
  std::sort(accounts.begin(), accounts.end());
  CHECK(std::adjacent_find(accounts.begin(), accounts.end()) == accounts.end());
  block::gen::ShardStateUnsplit::Record state;
  CHECK(tlb::unpack_cell(load(fixture / "current-state.boc"), state));
  vm::AugmentedDictionary dictionary(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  block::WorkchainAccountDeclarations declarations;
  for (const auto& key : accounts) {
    block::Account old(2, key.bits());
    CHECK(old.unpack(dictionary.lookup(key), state.gen_utime, false));
    CHECK(old.total_state.not_null());
    declarations.reads.push_back({key, td::Bits256(old.total_state->get_hash().bits())});
    declarations.writes.push_back(key);
  }
  save(fixture / "operation.candidate.boc", std::move(candidate));
  save(fixture / "operation.declarations.boc",
       block::encode_workchain_account_declarations(declarations, 4, 4).move_as_ok());
}
inline std::vector<td::Bits256> wallet_words(const std::string& hex) {
  const auto bytes = td::hex_decode(hex).move_as_ok();
  CHECK(bytes.size() % 32 == 0);
  std::vector<td::Bits256> words;
  for (std::size_t offset = 0; offset < bytes.size(); offset += 32) {
    td::Bits256 value;
    value.as_slice().copy_from(td::Slice(bytes).substr(offset, 32));
    words.push_back(value);
  }
  return words;
}
inline void prepare_debit(const std::filesystem::path& fixture, bool finish, bool quote = false) {
  auto env = wallet_environment(fixture, 1); env.protocol.kind = 5;
  const auto predecessor = account_data(load(fixture / "current-state.boc"), wallet_account(0));
  auto old = m5_live_account(predecessor, m5_live_withdrawal_limit(fixture)).account;
  old.schema_version = env.account_schema; // Crypto projection, not the committed predecessor.
  auto zero = load(fixture / "zerostate.boc");
  tos::BlockIdExt zid{tos::BlockId{tos::masterchainId,tos::shardIdAll,0},zero->get_hash().bits(),td::Bits256::zero()};
  auto cfg = block::ConfigInfo::extract_config(zero,zid,block::Config::needWorkchainInfo | block::Config::needCapabilities).move_as_ok();
  auto ingress = block::load_workchain_native_ingress_table(*cfg).move_as_ok().at(2);
  auto business = block::m3_test::decode_m3_test_business_parameters(
      block::decode_workchain_engine_parameters(ingress.engine_configuration).move_as_ok().parameters).move_as_ok();
  CHECK(business.prepare && business.operation_tariff);
  auto points = quote ? std::vector<td::Bits256>(3) : wallet_words(field(fixture / "operation.points.txt", "points")); CHECK(points.size()==3);
  auto number = [&](const char* key) {return std::stoull(field(fixture / "operation.request.txt",key));};
  auto wid = block::derive_workchain_withdrawal_id(block::confidential_execution_detail::network(env),old.address,old.auth_nonce).move_as_ok();
  auto aid = block::derive_workchain_attempt_id(wid).move_as_ok();
  block::WorkchainWithdrawalInput input{wid,aid,
      {{old.address, old.auth_nonce, old.available_revision, old.key_epoch, UINT32_MAX, number("fee")},
       {0,wallet_account(1)}, {number("principal"),number("outward_fee"),number("fee")},
       {points[0],points[1]},points[2]}, {}};
  if (quote) {
    block::gen::ShardStateUnsplit::Record state;
    CHECK(tlb::unpack_cell(load(fixture / "current-state.boc"), state));
    vm::AugmentedDictionary dictionary(vm::load_cell_slice_ref(state.accounts),256,block::tlb::aug_ShardAccounts);
    block::Account payer(2, env.rules.custody.bits());
    CHECK(payer.unpack(dictionary.lookup(env.rules.custody),state.gen_utime,false));
    auto prices = block::m3_test::m5_payout_prices(*cfg,state.gen_utime).move_as_ok();
    auto request = block::m3_test::m5_payout_request(input).move_as_ok();
    std::uint64_t start;
    CHECK(!__builtin_add_overflow(payer.last_trans_end_lt_,std::uint64_t{1},&start));
    auto priced = block::transaction::Transaction::price_workchain_payout(payer,request,start,state.gen_utime,
        payer.balance.tomis,prices).move_as_ok();
    td::write_file((fixture / "payout.quote.txt").string(),priced.total_fee->to_dec_string()+"\n").ensure();
    return;
  }
  auto context = block::m3_test::m5_debit_context(env,*business.prepare,old,input,predecessor).move_as_ok();
  if (finish) {
    input.authorization = {wallet_words(field(fixture / "operation.proof.txt","commitments")),
        wallet_words(field(fixture / "operation.proof.txt","responses")),
        td::hex_decode(field(fixture / "operation.proof.txt","range_proof")).move_as_ok()};
    save_operation(fixture,block::m3_test::wrap_m5_test_debit(block::encode_workchain_withdrawal_input(input).move_as_ok()),
        {wallet_account(0),env.rules.custody});
  } else {
    td::write_file((fixture / "operation.statement.txt").string(),
        "context="+td::hex_encode(context)+"\ndomain="+td::hex_encode(td::Slice(env.domain.data(),env.domain.size()))+
        "\nwithdrawal_id="+td::hex_encode(wid.as_slice())+"\nattempt_id="+td::hex_encode(aid.as_slice())+"\n").ensure();
  }
}
inline void prepare_transfer(const std::filesystem::path& fixture, bool finish, unsigned kind) {
  const auto parsed_owner = std::stoul(field(fixture / "operation.wallet.txt", "owner"));
  CHECK(parsed_owner < 2);
  const auto owner = static_cast<unsigned>(parsed_owner);
  const auto env = wallet_environment(fixture, kind);
  const auto points = wallet_words(field(fixture / "operation.points.txt", "points"));
  auto prepared = (kind == 1 ? block::m3_test::prepare_m3_test_send(env, wallet_state(fixture, owner),
      wallet_state(fixture, owner == 0 ? 1 : 0), UINT32_MAX, points)
      : block::m3_test::prepare_m3_test_collect(env, wallet_state(fixture, owner), UINT32_MAX,
          wallet_words(field(fixture / "operation.wallet.txt", "selected")), points)).move_as_ok();
  if (finish) {
    block::WorkchainTransferAuthorization authorization{
        wallet_words(field(fixture / "operation.proof.txt", "commitments")),
        wallet_words(field(fixture / "operation.proof.txt", "responses")),
        td::hex_decode(field(fixture / "operation.proof.txt", "range_proof")).move_as_ok()};
    auto participants = kind == 1 ? std::vector<td::Bits256>{wallet_account(0), wallet_account(1)}
                                  : std::vector<td::Bits256>{wallet_account(owner)};
    // M4's authenticated profile uses explicit D32 fee settlement; custody is
    // an actual Native participant, never an off-chain balance adjustment.
    if (env.proof_profile == 4) participants.push_back(env.rules.custody);
    save_operation(fixture, block::m3_test::finish_m3_test_transfer(prepared, std::move(authorization)).move_as_ok(),
                   std::move(participants));
    return;
  }
  std::string text;
  for (const auto& [key, value] : prepared.prover_fields) text += key + "=" + value + "\n";
  td::write_file((fixture / "operation.statement.txt").string(), text).ensure();
}
inline void prepare_closure(const std::filesystem::path& fixture, bool finish) {
  const auto env = wallet_environment(fixture, 1);
  const auto& p = env.protocol;
  block::WorkchainPossessionPolicy policy{
      {p.engine_version, p.relation_version, p.wire_version, p.proof_version,
       p.global_id, p.workchain_id, p.genesis_hash, p.workchain_instance},
      env.rules, env.profiles, env.fee_profile, env.fee_effective_height};
  const unsigned owner = std::filesystem::exists(fixture / "closure.owner.txt")
      ? std::stoul(field(fixture / "closure.owner.txt", "owner")) : (env.proof_profile == 4 ? 0 : 1);
  CHECK(owner < 2);
  const auto account = wallet_state(fixture, owner);
  const auto prepared = block::m3_test::make_m3_test_closure_wallet_input(policy, env.domain, account).move_as_ok();
  if (finish) {
    const auto bytes = td::hex_decode(field(fixture / "closure.proof.txt", "proof")).move_as_ok();
    CHECK(bytes.size() == 96);
    block::WorkchainClosureReplayInput input{prepared.operation_id, prepared.context, {}};
    std::memcpy(input.proof.data(), bytes.data(), bytes.size());
    save_operation(fixture, block::encode_workchain_replay_input(input).move_as_ok(), {wallet_account(owner)});
    return;
  }
  td::write_file((fixture / "closure.request.txt").string(),
      std::string(owner == 0 ? "secret=101\ncontext=" : "secret=223\ncontext=") + td::hex_encode(prepared.context_bytes) +
      "\nprefix=" + td::hex_encode(prepared.prefix_bytes) +
      "\nhandle=" + td::hex_encode(account.available.handle.as_slice()) +
      "\ncommitment=" + td::hex_encode(account.available.commitment.as_slice()) + "\n").ensure();
}
}  // namespace m3_live
