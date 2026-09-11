// TEST-OWNED NODE DRIVER. No deployment configuration may enable D59 execution.
// Reuse the disk tool's real actor startup/DB path, not a simulated collator.
#define main disk_collator_tool_main
#include "test-tos-collator.cpp"
#undef main
#include <filesystem>
#include <sys/wait.h>
#include "crypto/test/workchain-m3-node-engine.h"
#include "m3-live-config.h"
#include "m3-live-registration.h"
#include "m3-live-state.h"
#include "m5-live-return.h"
#include "m5-live-reserve-control.h"
#include "m3-live-assertions.h"
#include "m3-live-wallet.h"
#include "m4-live-deposit.h"

int main(int argc, char** argv) {
  if (argc == 3 && std::string(argv[1]) == "--withdrawal-payout-quote") {
    vm::init_vm().ensure();
    m3_live::prepare_debit(argv[2], false, true); return 0;
  }
  if (argc == 3 && (std::string(argv[1]) == "--withdrawal-debit-request" || std::string(argv[1]) == "--withdrawal-debit-finish")) {
    vm::init_vm().ensure();
    m3_live::prepare_debit(argv[2], std::string(argv[1]).ends_with("finish"));
    return 0;
  }
  if ((argc == 3 || argc == 4) && std::string(argv[1]) == "--check-m5-reserve-admission") {
    vm::init_vm(true).ensure();
    m3_live::check_m5_reserve_admission(std::filesystem::path(argv[2]), argc == 4 ? std::stoi(argv[3]) : 0);
    return 0;
  }
  if (argc == 3 && std::string(argv[1]) == "--observe-m5-payout-recipient") {
    vm::init_vm(true).ensure();
    m3_live::observe_m5_payout_recipient(std::filesystem::path(argv[2]));
    return 0;
  }
  if (argc == 3 && std::string(argv[1]) == "--check-m4-bounce-received") {
    vm::init_vm().ensure();
    const std::filesystem::path fixture(argv[2]);
    CHECK(std::filesystem::exists(fixture / ".counter-managed-v1"));
    m3_live::assert_m4_bounce_received(fixture);
    return 0;
  }
  if (argc == 3 && std::string(argv[1]) == "--inspect-m4-final") {
    vm::init_vm().ensure();
    const std::filesystem::path fixture(argv[2]);
    CHECK(std::filesystem::exists(fixture / ".counter-managed-v1"));
    const auto root = m3_live::load(fixture / "accepted-state.boc");
    const auto coordinator = block::decode_workchain_coordinator_state(
        m3_live::account_data(root, td::Bits256::zero())).move_as_ok();
    std::cout << "registered_accounts=" << coordinator.system.registered_accounts << '\n';
    for (const auto byte : {0x11, 0x22}) {
      td::Bits256 address;
      address.as_slice().fill(static_cast<char>(byte));
      const auto account = block::decode_workchain_confidential_account(
          m3_live::account_data(root, address)).move_as_ok();
      std::cout << (byte == 0x11 ? "A" : "B") << " system_slots=" << account.system_pending.size()
                << " user_slots=" << account.pending.size() << '\n';
      CHECK(account.system_pending.empty() && account.pending.empty());
    }
    block::gen::ShardStateUnsplit::Record state;
    CHECK(tlb::unpack_cell(root, state));
    vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
    block::Account native(2, td::Bits256::zero().bits());
    CHECK(native.unpack(accounts.lookup(td::Bits256::zero()), state.gen_utime, false));
    std::cout << "coordinator_native=" << native.balance.tomis << '\n';
    block::CurrencyCollection total(0);
    for (unsigned seqno = 1; seqno <= 9; ++seqno) {
      block::gen::Block::Record record;
      CHECK(tlb::unpack_cell(m3_live::load(fixture / "m4-blocks" /
            (std::to_string(seqno) + ".boc")), record));
      block::ValueFlow flow;
      CHECK(flow.unpack(vm::load_cell_slice_ref(record.value_flow)));
      block::CurrencyCollection next;
      CHECK(block::CurrencyCollection::add(total, flow.fees_collected, next));
      total = std::move(next);
      std::cout << "block=" << seqno << " fees_collected=" << flow.fees_collected.tomis << '\n';
    }
    std::cout << "nine_wc2_blocks_fees_collected=" << total.tomis << '\n';
    return 0;
  }
  if (argc == 3 && std::string(argv[1]) == "--check-m4-master") {
    vm::init_vm().ensure();
    const std::filesystem::path fixture(argv[2]);
    CHECK(std::filesystem::exists(fixture / ".counter-managed-v1"));
    m3_live::assert_m4_master_import(fixture);
    return 0;
  }
  if (argc == 3 && std::string(argv[1]) == "--wallet-policy") {
    vm::init_vm().ensure();
    const std::filesystem::path fixture(argv[2]);
    CHECK(std::filesystem::exists(fixture / ".counter-managed-v1"));
    const auto send = m3_live::wallet_environment(fixture, 1);
    const auto collect = m3_live::wallet_environment(fixture, 2);
    td::write_file((fixture / "wallet-policy.txt").string(),
        "send_fee=" + std::to_string(send.execution_fee) + "\ncollect_fee=" + std::to_string(collect.execution_fee) +
        "\nmax_balance=" + std::to_string(send.limits.max_balance) +
        "\nmax_value=" + std::to_string(send.limits.max_value) + "\n").ensure();
    return 0;
  }
  if (argc == 3 && std::string(argv[1]) == "--collect-receipts") {
    vm::init_vm().ensure();
    const std::filesystem::path fixture(argv[2]);
    CHECK(std::filesystem::exists(fixture / ".counter-managed-v1"));
    const auto owner = std::stoul(m3_live::field(fixture / "operation.wallet.txt", "owner"));
    CHECK(owner < 2);
    const auto ids = m3_live::wallet_words(m3_live::field(fixture / "operation.wallet.txt", "selected"));
    // This live sequence selects exactly one entry at a time. Reuse B's
    // multi-source helper, not a separate ciphertext/receipt codec.
    CHECK(ids.size() == 1);
    auto fields = block::m3_test::prepare_m4_test_collect_receipt_fields(
        m3_live::wallet_state(fixture, static_cast<unsigned>(owner)), ids,
        {std::stoull(m3_live::field(fixture / "operation.wallet.txt", "value"))}).move_as_ok();
    std::string text;
    for (const auto& [key, value] : fields) text += key + "=" + value + "\n";
    td::write_file((fixture / "operation.receipts.txt").string(), text).ensure();
    return 0;
  }
  if (argc == 3 && std::string(argv[1]) == "--deposit-request") {
    vm::init_vm().ensure();
    const std::filesystem::path fixture(argv[2]);
    CHECK(std::filesystem::exists(fixture / ".counter-managed-v1"));
    m3_live::prepare_m4_deposit(fixture);
    return 0;
  }
  if (argc == 3 && std::string(argv[1]) == "--m4-backing-control") {
    const std::string mode(argv[2]);
    if (mode != "unpaired" && mode != "cross-block-d" && mode != "restored") return 2;
    auto status = m3_live::check_m4_backing(td::make_refint(mode == "unpaired" ? 1 : 0),
        td::make_refint(0), td::make_refint(mode == "cross-block-d" ? 1 : 0));
    std::cout << "M4 backing control " << mode << ": "
              << (status.is_ok() ? "OK" : status.message().str()) << '\n';
    return status.is_ok() ? 0 : 1;
  }
  // Make the zero-stage block check demonstrably capable of rejecting a
  // discrepancy, rather than only exercising equality of three constants.
  m3_live::check_m4_backing(td::make_refint(0), td::make_refint(0), td::make_refint(0)).ensure();
  CHECK(m3_live::check_m4_backing(td::make_refint(1), td::make_refint(0), td::make_refint(0)).is_error());
  CHECK(m3_live::check_m4_backing(td::make_refint(0), td::make_refint(1), td::make_refint(0)).is_error());
  CHECK(m3_live::check_m4_backing(td::make_refint(0), td::make_refint(0), td::make_refint(1)).is_error());
  if (argc == 3 && std::string(argv[1]) == "--check-closure-result") {
    vm::init_vm().ensure();
    const std::filesystem::path fixture(argv[2]);
    CHECK(std::filesystem::exists(fixture / ".counter-managed-v1"));
    auto previous = m3_live::load(fixture / "current-state.boc");
    auto accepted = m3_live::read_accepted_step(fixture / "enabled.candidate", previous);
    block::gen::Transaction::Record tx;
    CHECK(tlb::unpack_cell(m3_live::accepted_transaction(accepted, td::Bits256::zero()), tx));
    auto input = block::m3_test::replay_input_from_block(accepted.block, td::Bits256::zero(), tx.lt).move_as_ok();
    auto replay = block::decode_workchain_replay_input(input).move_as_ok();
    CHECK(std::holds_alternative<block::WorkchainClosureReplayInput>(replay));
    m3_live::assert_accepted_closure(previous, accepted,
        std::get<block::WorkchainClosureReplayInput>(replay).context.subject.account);
    return 0;
  }
  if (argc == 3 && (std::string(argv[1]) == "--closure-request" || std::string(argv[1]) == "--closure-finish")) {
    vm::init_vm().ensure();
    const std::filesystem::path fixture(argv[2]);
    CHECK(std::filesystem::exists(fixture / ".counter-managed-v1"));
    m3_live::prepare_closure(fixture, std::string(argv[1]) == "--closure-finish");
    return 0;
  }
  if (argc == 3 && (std::string(argv[1]) == "--send-request" || std::string(argv[1]) == "--send-finish" ||
                   std::string(argv[1]) == "--collect-request" || std::string(argv[1]) == "--collect-finish")) {
    vm::init_vm().ensure();
    const std::filesystem::path fixture(argv[2]);
    CHECK(std::filesystem::exists(fixture / ".counter-managed-v1"));
    const std::string mode(argv[1]);
    m3_live::prepare_transfer(fixture, mode.ends_with("finish"), mode.starts_with("--send") ? 1 : 2);
    return 0;
  }
  if (argc == 3 && std::string(argv[1]) == "--test-funding-request") {
    vm::init_vm().ensure();
    const std::filesystem::path fixture(argv[2]);
    CHECK(std::filesystem::exists(fixture / ".counter-managed-v1"));
    auto bytes = td::hex_decode(m3_live::field(fixture / "seed.result.txt", "available")).move_as_ok();
    CHECK(bytes.size() == 64);
    block::WorkchainCiphertext available;
    available.commitment.as_slice().copy_from(td::Slice(bytes).substr(0, 32));
    available.handle.as_slice().copy_from(td::Slice(bytes).substr(32, 32));
    td::Bits256 account;
    account.as_slice().fill(0x11);
    m3_live::save_operation(fixture, block::m3_test::encode_m3_test_funding({account, available}), {account});
    std::cout << "Test-only block-contained funding requested; NOT M4 Deposit.\n";
    return 0;
  }
  if (argc == 3 && (std::string(argv[1]) == "--registration-request" ||
                    std::string(argv[1]) == "--registration-request-b" ||
                    std::string(argv[1]) == "--registration-finish")) {
    vm::init_vm().ensure();
    const std::filesystem::path fixture(argv[2]);
    CHECK(std::filesystem::exists(fixture / ".counter-managed-v1"));
    if (std::string(argv[1]) == "--registration-request") m3_live::registration_request(fixture);
    else if (std::string(argv[1]) == "--registration-request-b") m3_live::registration_request(fixture, 1);
    else m3_live::registration_finish(fixture);
    return 0;
  }
  if (argc == 3 && (std::string(argv[1]) == "--prepare-config" || std::string(argv[1]) == "--prepare-m4-config" || std::string(argv[1]) == "--prepare-m5-debit-config" || std::string(argv[1]) == "--prepare-m5-return-config")) {
    vm::init_vm().ensure();
    const std::filesystem::path fixture(argv[2]);
    CHECK(std::filesystem::exists(fixture / ".counter-managed-v1"));
    auto bytes = td::read_file_str((fixture / "zerostate.boc").string()).move_as_ok();
    auto root = prepare_m3_live_configuration(vm::std_boc_deserialize(bytes).move_as_ok(),
        std::string(argv[1]) != "--prepare-config", std::string(argv[1]) == "--prepare-m5-debit-config",
        std::string(argv[1]) == "--prepare-m5-return-config").move_as_ok();
    td::write_file((fixture / "zerostate.boc").string(), vm::std_boc_serialize(root, 31).move_as_ok()).ensure();
    td::write_file((fixture / "zerostate.rhash").string(), root->get_hash().as_slice()).ensure();
    return 0;
  }
  if (argc == 3 && (std::string(argv[1]) == "--coordinator-data" || std::string(argv[1]) == "--m4-coordinator-data")) {
    vm::init_vm().ensure();
    // Assumed TEST initial coordinator state; no registrations or deposits.
    // This mode writes only a caller-owned fixture file, never deployment state.
    block::WorkchainCoordinatorState state{2, {1, 1, 0, 0}, 0};
    if (std::string(argv[1]) == "--m4-coordinator-data") {
      auto bucket = block::encode_workchain_unexpected_bucket({{}, {}, td::make_refint(0), {}, 0},
                                                              {256, 256}, 4096).move_as_ok();
      state = {3, {1, 1, 0, 0}, 0, 0, bucket};
    }
    auto data = block::encode_workchain_coordinator_state(state).move_as_ok();
    td::write_file(td::CSlice(argv[2]), vm::std_boc_serialize(data).move_as_ok()).ensure();
    return 0;
  }
  if (argc != 2) return 2;
  const std::filesystem::path fixture(argv[1]);
  if (!std::filesystem::exists(fixture / "prepare.cmake") ||
      !std::filesystem::exists(fixture / ".counter-managed-v1")) return 2;
  vm::init_vm().ensure();
  auto bytes = td::read_file_str((fixture / "zerostate.boc").string()).move_as_ok();
  auto root = vm::std_boc_deserialize(bytes).move_as_ok();
  tos::BlockIdExt zero{tos::BlockId{tos::masterchainId, tos::shardIdAll, 0},
                       root->get_hash().bits(), td::Bits256::zero()};
  auto config = block::ConfigInfo::extract_config(root, zero,
      block::Config::needWorkchainInfo | block::Config::needCapabilities).move_as_ok();
  // Proposer input acquisition only. Validator replay must obtain authorization
  // from the resulting serialized block, never from either of these files.
  auto candidate = vm::std_boc_deserialize(
      td::read_file_str((fixture / "operation.candidate.boc").string()).move_as_ok()).move_as_ok();
  auto declarations = vm::std_boc_deserialize(
      td::read_file_str((fixture / "operation.declarations.boc").string()).move_as_ok()).move_as_ok();
  const bool test_funding = block::m3_test::is_m3_test_funding(candidate);
  const bool deposit = block::m3_test::is_m4_test_deposit(candidate);
  const bool debit = block::m3_test::is_m5_test_debit(candidate);
  const auto ingress = block::load_workchain_native_ingress_table(*config).move_as_ok().at(2);
  const auto params = block::decode_workchain_engine_parameters(ingress.engine_configuration).move_as_ok();
  const bool m4 = block::m3_test::decode_m3_test_business_parameters(params.parameters).move_as_ok().deposit.has_value();
  unsigned transaction_count = 2;
  if (deposit || debit) transaction_count = 3;
  else if (!test_funding) {
    const auto operation = block::decode_workchain_replay_input(candidate).move_as_ok();
    const auto* transfer = std::get_if<block::WorkchainTransferInput>(&operation);
    if (transfer) transaction_count =
        (std::holds_alternative<block::WorkchainSendData>(transfer->data) ? 3 : 2) + (m4 ? 1 : 0);
  }
  for (const bool enabled : {false, true}) {
    const std::string name = enabled ? "enabled" : "closed";
    auto db = fixture / (name + "-db");
    std::filesystem::copy(fixture / "db", db, std::filesystem::copy_options::recursive);
    const auto result = (fixture / (name + ".result")).string();
    const auto counter = (fixture / (name + ".calls")).string();
    const auto exported = (fixture / (name + ".candidate")).string();
    const auto pid = fork();
    if (pid < 0) return 2;
    if (pid == 0) {
      disk_collator_test_options_setup = [&](tos::validator::ValidatorManagerOptions& options) {
        auto collator = td::make_ref<tos::validator::CollatorOptions>();
        collator.write().workchain_account_candidate_source =
            [candidate, declarations](tos::ShardIdFull shard) -> td::Result<block::WorkchainAccountCandidate> {
          if (shard.workchain != 2 || shard.shard != tos::shardIdAll)
            return td::Status::Error(-7201, "M3 test input is scoped to wc=2 unsplit shard");
          return block::WorkchainAccountCandidate{candidate, declarations};
        };
        options.set_collator_options(collator);
      };
      disk_collator_test_engine_setup = [&] {
        auto& registry = block::default_workchain_execution_registry();
        registry.register_account_engine(std::make_unique<block::m3_test::M3NodeEngine>(
            block::WorkchainEngineKey{block::WorkchainFormat::Basic, 0x434e5431}, counter)).ensure();
        auto resolved = registry.resolve_scoped_workchain(2, *config).move_as_ok();
        CHECK(resolved && std::holds_alternative<block::ResolvedWorkchainAccountBinding>(*resolved));
        const auto& binding = std::get<block::ResolvedWorkchainAccountBinding>(*resolved);
        // Owner's 2026-09-09 test-constructed configuration shape, scoped by D59.
        // enabled is the fixed paired-test loop above, never a CLI/config/env bit.
        registry.enable_test_only_account_instance_execution(
            2, block::decode_workchain_engine_parameters(binding.ingress.engine_configuration).move_as_ok().instance_id,
            enabled).ensure();
      };
      const auto previous = std::filesystem::exists(fixture / "accepted-block.id")
          ? td::read_file_str((fixture / "accepted-block.id").string()).move_as_ok()
          : "(2,8000000000000000,0):" +
              td::hex_encode(td::read_file_str((fixture / "counter-state.rhash").string()).move_as_ok()) + ":" +
              td::hex_encode(td::read_file_str((fixture / "counter-state.fhash").string()).move_as_ok());
      std::vector<std::string> args{"test-m3-live", "-C", (fixture / "global.json").string(),
          "-D", db.string(), "-w", "2", "-T", previous,
          "--query-result", result, "--export-candidate", exported,
          "-s", (fixture / (name + "-top")).string()};
      std::vector<char*> raw;
      for (auto& value : args) raw.push_back(value.data());
      raw.push_back(nullptr);
      std::_Exit(disk_collator_tool_main(static_cast<int>(args.size()), raw.data()));
    }
    int status;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != (enabled ? 0 : 2)) return 2;
    auto read = [&](const std::string& suffix) { return td::read_file_str(result + suffix).move_as_ok(); };
    const auto observation = read(".readiness");
    // Missing/unknown observation is not evidence of a closed gate.
    const std::string expected = enabled ? "phase=4\nworkchain=2\ndelivery=recorded\n"
                                         : "phase=3\nworkchain=2\ndelivery=recorded\n";
    const auto stats = read(".stats");
    const auto calls = td::read_file_str(counter).move_as_ok();
    if (enabled) {
      if (observation != "phase=4\nworkchain=2\ndelivery=recorded\n" ||
          read(".kind") != "success\n" || read("") != "collate 0\n" ||
          read(".validation.kind") != "accept\n" || read(".validation.result") != "validate accept\n" ||
          read(".validation.delivery") != "recorded\n" ||
          stats != "delivery=recorded\nvisited=1\nadapter=1\nowners_before=1\nowners_during=2\nowners_after=1\ntransactions=" +
              std::to_string(transaction_count) + "\n" ||
          calls != "config=9\nexecute=2\n" || !std::filesystem::exists(exported)) {
        std::cerr << "Unexpected enabled operation observation: " << observation << stats << calls;
        return 2;
      }
      auto previous = m3_live::load(fixture / "current-state.boc");
      const auto collation_units = td::read_file_str(counter + ".units.1").move_as_ok();
      const auto replay_units = td::read_file_str(counter + ".units.2").move_as_ok();
      CHECK(collation_units == replay_units && !collation_units.empty());
      CHECK(!std::filesystem::exists(counter + ".units.3"));
      std::cout << "Paired proof-work units collator=validator=" << collation_units;
      auto accepted = m3_live::read_accepted_step(exported, previous);
      if (debit) {
        auto operation = block::m3_test::decode_m5_test_debit(candidate).move_as_ok();
        const auto key = operation.data.claims.source.account;
        auto old = block::decode_workchain_confidential_account(m3_live::account_data(previous,key)).move_as_ok();
        auto complete = m3_live::m5_live_account(m3_live::account_data(accepted.state,key),m3_live::m5_live_withdrawal_limit(fixture));
        auto next = complete.account;
        CHECK(complete.control.withdrawals.size() == 1);
        const auto& obligation = complete.control.withdrawals.front();
        CHECK(obligation.principal == operation.data.amounts.principal);
        const auto custody_key = block::load_workchain_native_ingress_table(*config).move_as_ok().at(2).custody_address;
        CHECK(custody_key);
        block::gen::Transaction::Record payout_tx;
        CHECK(tlb::unpack_cell(m3_live::accepted_transaction(accepted,*custody_key),payout_tx));
        vm::Dictionary outputs(payout_tx.r1.out_msgs,15);
        const auto payout = outputs.lookup_ref(td::BitArray<15>::zero());
        CHECK(payout.not_null() && payout_tx.outmsg_cnt == 1);
        block::gen::Message::Record payout_wire;
        block::gen::CommonMsgInfo::Record_int_msg_info payout_info;
        CHECK(tlb::type_unpack_cell(payout,block::gen::t_Message_Any,payout_wire) && tlb::csr_unpack(payout_wire.info,payout_info));
        CHECK(payout_info.created_lt == obligation.timing.payout_created_lt && obligation.timing.phase == 0);
        CHECK(block::tlb::t_Tomis.as_integer(payout_info.extra_flags)->to_long() == 3);
        CHECK(obligation.withdrawal_id == operation.claimed_operation_id && obligation.attempt_id == operation.claimed_attempt_id);
        block::CurrencyCollection payment; CHECK(payment.unpack(payout_info.value));
        CHECK(payment == block::CurrencyCollection(block::workchain_unsigned_fee(operation.data.amounts.principal)));
        block::gen::ShardStateUnsplit::Record published;
        block::gen::OutMsgQueueInfo::Record queue_info;
        CHECK(tlb::unpack_cell(accepted.state,published) && tlb::unpack_cell(published.out_msg_queue_info,queue_info));
        vm::AugmentedDictionary queue(queue_info.out_queue,352,block::tlb::aug_OutMsgQueue);
        unsigned found = 0;
        CHECK(queue.check_for_each([&](td::Ref<vm::CellSlice> value, td::ConstBitPtr queue_key, int bits) {
          block::EnqueuedMsgDescr entry;
          unsigned long long augmentation;
          CHECK(bits == 352 && value.write().fetch_ulong_bool(64,augmentation) && entry.unpack(value.write()) && entry.check_key(queue_key));
          if (entry.msg_->get_hash() == payout->get_hash()) {
            CHECK(entry.lt_ == obligation.timing.payout_created_lt); ++found;
          }
          return true;
        }));
        CHECK(found == 1);
        m3_live::save(fixture / "prepare-payout.boc",payout);
        std::cout << "WITHDRAWAL_ENQUEUED hash=" << payout->get_hash().to_hex()
                  << " created_lt=" << payout_info.created_lt << " x=" << obligation.principal
                  << " q=" << obligation.costs.outward_fee_paid << " b=" << obligation.costs.original_reserve << std::endl;
        auto expected = block::next_workchain_confidential_counters(old,old.auth_nonce,old.available_revision).move_as_ok();
        CHECK(next.auth_nonce == expected.auth_nonce && next.available_revision == expected.available_revision);
        CHECK(next.available.commitment == operation.data.available.commitment && next.available.handle == operation.data.available.handle);
        CHECK(next.available.commitment != old.available.commitment);
        const auto before_value = std::stoull(m3_live::field(fixture / "operation.expected.txt","before"));
        const auto after_value = std::stoull(m3_live::field(fixture / "operation.expected.txt","after"));
        CHECK(after_value < before_value);
        block::m3_test::assert_balance(block::m3_test::decrypt(old.available,m3_live::test_secret(key),before_value).move_as_ok(),before_value).ensure();
        block::m3_test::assert_balance(block::m3_test::decrypt(next.available,m3_live::test_secret(key),before_value).move_as_ok(),after_value).ensure();
        m3_live::save(fixture / "debit-authenticated-state.boc",accepted.state);
        m3_live::save(fixture / "debit-authenticated-block.boc",accepted.block);
        std::cout << "WITHDRAWAL_DEBIT_AUTHENTICATED before=" << before_value << " after=" << after_value
                  << " revision=" << old.available_revision << "->" << next.available_revision << std::endl;
        // Read the obligation from the accepted root, not the proposed effects.
      }
      auto ingress_table = block::load_workchain_native_ingress_table(*config).move_as_ok();
      CHECK(ingress_table.count(2) && ingress_table.at(2).custody_address);
      if (m4) m3_live::assert_m4_block_backing(fixture, accepted, *ingress_table.at(2).custody_address);
      else m3_live::assert_pre_deposit_backing(accepted, *ingress_table.at(2).custody_address);
      auto transaction = m3_live::accepted_transaction(accepted, td::Bits256::zero());
      block::gen::Transaction::Record tx;
      CHECK(tlb::unpack_cell(transaction, tx));
      if (deposit) {
        if (m3_live::m4_deposit_was_rejected(accepted.block))
          m3_live::assert_rejected_deposit(fixture, previous, accepted, *ingress_table.at(2).custody_address);
        else m3_live::assert_accepted_deposit(fixture, previous, accepted);
      } else if (debit) {
        // Withdrawal is independently checked above and by the backing replay.
      } else if (test_funding) {
        block::gen::TransactionDescr::Record_trans_workchain_entry_v3 entry;
        block::gen::UnoV2HostInput::Record host;
        CHECK(tlb::unpack_cell(tx.description, entry) &&
              tlb::unpack_cell(entry.input, host));
        auto funding = block::m3_test::decode_m3_test_funding(host.candidate).move_as_ok();
        auto before = m3_live::account_data(previous, funding.account);
        auto after = m3_live::account_data(accepted.state, funding.account);
        auto recomputed = block::m3_test::apply_m3_test_funding(before, funding).move_as_ok();
        CHECK(recomputed->get_hash() == after->get_hash());
        CHECK(block::m3_test::apply_m3_test_funding(after, funding).is_error());
        auto record = block::decode_workchain_confidential_account(after).move_as_ok();
        block::m3_test::assert_balance(block::m3_test::decrypt(record.available,
            m3_live::test_secret(funding.account), 100000).move_as_ok(), 50000).ensure();
        std::cout << "Test-only block-contained funding accepted: A=50000; NOT M4 Deposit.\n";
      } else {
        auto recorded = block::m3_test::replay_input_from_block(accepted.block, td::Bits256::zero(), tx.lt).move_as_ok();
        auto replay = block::decode_workchain_replay_input(recorded).move_as_ok();
        if (const auto* registration = std::get_if<block::WorkchainRegistrationReplayInput>(&replay)) {
          block::m3_test::assert_registration(m3_live::account_data(previous, td::Bits256::zero()),
              m3_live::account_data(accepted.state, td::Bits256::zero()),
              m3_live::account_data(accepted.state, registration->context.subject.account)).ensure();
        } else if (std::holds_alternative<block::WorkchainTransferInput>(replay)) {
          m3_live::assert_accepted_transfer(fixture, previous, accepted);
        } else {
          const auto& closure = std::get<block::WorkchainClosureReplayInput>(replay);
          m3_live::assert_accepted_closure(previous, accepted, closure.context.subject.account,
              m4 ? std::stoull(m3_live::field(fixture / "closure.expected.txt", "other")) : 49490);
        }
      }
      m3_live::save(fixture / "accepted-state.boc", accepted.state);
      m3_live::save(fixture / "accepted-block.boc", accepted.block);
      td::write_file((fixture / "accepted-block.id").string(), accepted.id.to_str()).ensure();
      std::cout << "enabled: operation accepted " << accepted.id.to_str()
                << "; actual state read back; NOT seven-step completion\n";
      continue;
    }
    const std::string expected_stats = "delivery=recorded\nvisited=1\nadapter=1\nowners_before=1\n"
        "owners_during=2\nowners_after=1\ntransactions=0\n";
    // Includes the driver's configuration resolution, which identifies the
    // permitted instance before starting the actor; these are not proof calls.
    const std::string expected_calls = enabled ? "config=5\nexecute=0\n" : "config=3\nexecute=0\n";
    if (observation != expected || read(".kind") != "error\n" || read("") != "collate -7201\n" ||
        stats != expected_stats || calls != expected_calls || std::filesystem::exists(exported) ||
        std::filesystem::exists(counter + ".units.1")) {
      std::cerr << "Unexpected paired observation: " << observation << stats << calls;
      return 2;
    }
    std::cout << name << ": " << observation << read(".stats.timing") << std::flush;
  }
  std::cout << "Paired closed registry refusal / accepted operation; NOT full live sequence acceptance.\n";
  return 0;
}
