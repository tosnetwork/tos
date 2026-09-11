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
#include "m3-live-assertions.h"
#include "m3-live-wallet.h"

int main(int argc, char** argv) {
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
  if (argc == 3 && std::string(argv[1]) == "--prepare-config") {
    vm::init_vm().ensure();
    const std::filesystem::path fixture(argv[2]);
    CHECK(std::filesystem::exists(fixture / ".counter-managed-v1"));
    auto bytes = td::read_file_str((fixture / "zerostate.boc").string()).move_as_ok();
    auto root = prepare_m3_live_configuration(vm::std_boc_deserialize(bytes).move_as_ok()).move_as_ok();
    td::write_file((fixture / "zerostate.boc").string(), vm::std_boc_serialize(root, 31).move_as_ok()).ensure();
    td::write_file((fixture / "zerostate.rhash").string(), root->get_hash().as_slice()).ensure();
    return 0;
  }
  if (argc == 3 && std::string(argv[1]) == "--coordinator-data") {
    vm::init_vm().ensure();
    // Assumed TEST initial coordinator state; no registrations or deposits.
    // This mode writes only a caller-owned fixture file, never deployment state.
    auto data = block::encode_workchain_coordinator_state({2, {1, 1, 0, 0}, 0}).move_as_ok();
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
  unsigned transaction_count = 2;
  if (!test_funding) {
    const auto operation = block::decode_workchain_replay_input(candidate).move_as_ok();
    const auto* transfer = std::get_if<block::WorkchainTransferInput>(&operation);
    if (transfer && std::holds_alternative<block::WorkchainSendData>(transfer->data)) transaction_count = 3;
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
      auto accepted = m3_live::read_accepted_step(exported, previous);
      auto transaction = m3_live::accepted_transaction(accepted, td::Bits256::zero());
      block::gen::Transaction::Record tx;
      CHECK(tlb::unpack_cell(transaction, tx));
      if (test_funding) {
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
          m3_live::assert_accepted_closure(previous, accepted, closure.context.subject.account);
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
        stats != expected_stats || calls != expected_calls || std::filesystem::exists(exported)) {
      std::cerr << "Unexpected paired observation: " << observation << stats << calls;
      return 2;
    }
    std::cout << name << ": " << observation << read(".stats.timing") << std::flush;
  }
  std::cout << "Paired closed registry refusal / accepted operation; NOT full live sequence acceptance.\n";
  return 0;
}
