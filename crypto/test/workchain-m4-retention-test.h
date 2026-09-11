#pragma once
// TEST ONLY. Persisted account transition, not a node/block acceptance claim.
#include "block/workchain-deposit-transition.h"
#include "workchain-m3-wallet-requests.h"
#include "workchain-m4-wallet-receipts.h"

inline td::Status test_m4_system_retention(const std::string& executable, const std::string& directory) {
  std::filesystem::create_directories(directory);
  unsigned request = 0;
  auto wallet = [&](const std::string& mode, const Text& fields) -> td::Result<Text> {
    auto path = std::filesystem::path(directory) / std::to_string(++request);
    auto input = path.string() + ".request", output = path.string() + ".result";
    {
      std::ofstream file(input);
      if (!file.good()) return alarm("cannot write test wallet request");
      for (const auto& [key, value] : fields) file << key << '=' << value << '\n';
      if (!file.good()) return alarm("test wallet request write failed");
    }
    if (std::system((quote(executable) + " " + quote(mode) + " " + quote(input) + " " + quote(output)).c_str()))
      return alarm("system COLLECT wallet command failed");
    return read(output);
  };
  auto persist = [&](const Root& root, const char* name) -> td::Result<Root> {
    TRY_RESULT(bytes, vm::std_boc_serialize(root, 0));
    auto path = (std::filesystem::path(directory) / name).string();
    TRY_STATUS(td::write_file(path, bytes.as_slice()));
    TRY_RESULT(stored, td::read_file_str(path));
    return vm::std_boc_deserialize(stored);
  };
  auto key = [](unsigned n) { auto b = td::Bits256::zero(); b.as_slice()[31] = static_cast<char>(n); return b; };
  TRY_RESULT(keys, wallet("key", {{"secret", "223"}}));
  WorkchainConfidentialAccount owner{2, 1, 4, -23903, key(1), {2, key(2), key(3)},
      {key(4), key(5), key(6)}, {10000000000ULL, 0, key(7)}, word(keys.at("public_key")), 0,
      {td::Bits256::zero(), td::Bits256::zero()}, 0, 0, {}, WorkchainAccountActive{}, {}};
  WorkchainDepositPolicy policy{1000000000, (std::uint64_t{1} << 62) - 1, 3000000, 16, 4};
  TRY_RESULT(empty, encode_workchain_unexpected_bucket({{}, {}, td::make_refint(0), {}, 0}, {256, 256}, 100));
  WorkchainCoordinatorState coordinator{3, {1, 0, 1, 4}, 10000000000ULL, 0, empty};
  CurrencyCollection backing(0), operating(10000000000ULL);
  std::array<unsigned char, 80> domain{};
  // Zero available is the real registration initial condition. Do not replace
  // it with an artificial nonidentity opening to hide first-COLLECT failures.
  for (unsigned i = 0; i < 2; ++i) {
    auto meter = WorkchainProofTestAccess::create(7);
    TRY_RESULT(result, prepare_workchain_deposit_transition(policy, domain, key(8), key(5), key(4),
        key(20 + i), owner.address, 1000000000, CurrencyCollection(1003000000),
        std::optional<WorkchainConfidentialAccount>{owner}, coordinator, backing, operating, {256, 256}, 100, meter));
    if (!std::holds_alternative<WorkchainDepositTransition>(result) || meter.consumed() != 7)
      return alarm("system retention Deposit setup did not execute");
    auto installed = std::get<WorkchainDepositTransition>(std::move(result));
    TRY_RESULT(stored, persist(installed.account_data, "account.boc"));
    TRY_RESULT(account, decode_workchain_confidential_account(stored));
    owner = std::move(account);
    TRY_RESULT(system, decode_workchain_coordinator_state(installed.coordinator_data));
    coordinator = std::move(system);
    backing = installed.custody_balance;
    operating = installed.coordinator_balance;
  }
  if (owner.system_pending.size() != 2) return alarm("two persisted system receipts missing");
  const auto selected = owner.system_pending[0].receipt_id;
  const auto retained = owner.system_pending[1];
  TRY_RESULT(retained_before, encode_workchain_deposit_receipt(retained));
  WorkchainTransferEnvironment env{};
  env.limits = {policy.maximum, policy.maximum, 8, 1024, 4096};
  env.domain = domain;
  env.protocol = {2, 1, 1, 4, 2, owner.global_id, 2, owner.genesis_hash, key(10)};
  env.rules = {key(4), key(5), key(6)};
  env.profiles = {key(11), key(12), key(13)};
  env.fee_profile = key(14);
  env.fee_effective_height = 1;
  env.height = 2;
  env.execution_fee = 17;
  env.pending_capacity = 16;
  env.account_schema = 2;
  env.relation_profile = 1;
  env.proof_profile = 4;
  TRY_RESULT(fields, prepare_m4_test_collect_receipt_fields(owner, {selected}, {1000000000}));
  fields.insert({{"secret", "223"}, {"old_value", "0"}, {"old_blind", "0"},
      {"new_blind", "887"}, {"aux_blind", "431"}, {"auxiliaries", "503"},
      {"kind", "2"}, {"fee", "17"}, {"max_balance", std::to_string(policy.maximum)},
      {"max_value", std::to_string(policy.maximum)}});
  TRY_RESULT(points, wallet("points-receipts", fields));
  TRY_RESULT(prepared, prepare_m3_test_collect(env, owner, 100, {selected}, words(points.at("points"))));
  for (const auto& [name, value] : prepared.prover_fields) fields[name] = value;
  TRY_RESULT(proof, wallet("prove-receipts", fields));
  TRY_RESULT(range, td::hex_decode(proof.at("range_proof")));
  TRY_RESULT(candidate, finish_m3_test_transfer(prepared,
      {words(proof.at("commitments")), words(proof.at("responses")), std::move(range)}));
  TRY_RESULT(wire, persist(candidate, "collect.boc"));
  TRY_RESULT(input, decode_workchain_transfer_input(wire));
  auto meter = WorkchainProofTestAccess::create(100000);
  TRY_RESULT(effects, execute_workchain_confidential_transfer(env, input,
      std::optional<WorkchainConfidentialAccount>{owner}, std::optional<WorkchainConfidentialAccount>{}, meter));
  TRY_RESULT(stored, persist(effects.source_data, "after.boc"));
  TRY_RESULT(after, decode_workchain_confidential_account(stored));
  if (after.system_pending.size() != 1 || after.system_pending[0].receipt_id != retained.receipt_id ||
      !after.pending.empty() || after.auth_nonce != 1 || after.available_revision != 1 ||
      owner.system_pending.size() != 2 || owner.auth_nonce != 0 || meter.consumed() == 0)
    return alarm("system selection was not atomic or selected system receipt persisted");
  TRY_RESULT(retained_after, encode_workchain_deposit_receipt(after.system_pending[0]));
  if (retained_after->get_hash() != retained_before->get_hash())
    return alarm("unselected system receipt changed during persisted COLLECT");
  // A one-slot authenticated test policy must still see the retained slot full.
  auto full = policy;
  full.system_slots = 1;
  TRY_RESULT(decision, admit_workchain_deposit(full, key(30), after.address, key(4), key(5),
      1000000000, td::make_refint(1003000000), *coordinator.deposit_sequence,
      std::optional<WorkchainConfidentialAccount>{after}));
  if (!std::holds_alternative<WorkchainDepositRejection>(decision) ||
      std::get<WorkchainDepositRejection>(decision) != WorkchainDepositRejection::Capacity)
    return alarm("unselected system receipt no longer occupies its slot");
  Point secret{};
  secret[0] = 223;
  TRY_RESULT(value, decrypt(after.available, secret, 1000000000));
  TRY_STATUS(assert_balance(value, 999999983));
  auto replay = WorkchainProofTestAccess::create(100000);
  TRY_RESULT(independent, execute_workchain_confidential_transfer(env, input,
      std::optional<WorkchainConfidentialAccount>{owner}, std::optional<WorkchainConfidentialAccount>{}, replay));
  if (independent.source_data->get_hash() != stored->get_hash() || replay.consumed() != meter.consumed())
    return alarm("system COLLECT reconstruction or metering differs");
  std::cout << "persisted system COLLECT k=1: available=" << value
            << " retained=1 identical=yes occupied=yes units=" << meter.consumed()
            << '/' << replay.consumed() << "; not live block acceptance\n";
  // Bytes retained are not evidence of spendability. Produce a second real
  // proof using the first transition's persisted available and remaining ID.
  TRY_RESULT(second_fields, prepare_m4_test_collect_receipt_fields(after, {retained.receipt_id}, {1000000000}));
  for (const auto& [name, field] : fields) {
    if (name != "receipt_ciphertexts" && name != "values") second_fields[name] = field;
  }
  second_fields["old_value"] = std::to_string(value);
  second_fields["old_blind"] = "887";
  second_fields["new_blind"] = "889";
  second_fields["aux_blind"] = "433";
  second_fields["auxiliaries"] = "509";
  TRY_RESULT(second_points, wallet("points-receipts", second_fields));
  TRY_RESULT(second_prepared, prepare_m3_test_collect(env, after, 100, {retained.receipt_id},
      words(second_points.at("points"))));
  for (const auto& [name, field] : second_prepared.prover_fields) second_fields[name] = field;
  TRY_RESULT(second_proof, wallet("prove-receipts", second_fields));
  TRY_RESULT(second_range, td::hex_decode(second_proof.at("range_proof")));
  TRY_RESULT(second_candidate, finish_m3_test_transfer(second_prepared,
      {words(second_proof.at("commitments")), words(second_proof.at("responses")), std::move(second_range)}));
  TRY_RESULT(second_wire, persist(second_candidate, "collect-retained.boc"));
  TRY_RESULT(second_input, decode_workchain_transfer_input(second_wire));
  auto second_meter = WorkchainProofTestAccess::create(100000);
  TRY_RESULT(second_effects, execute_workchain_confidential_transfer(env, second_input,
      std::optional<WorkchainConfidentialAccount>{after}, std::optional<WorkchainConfidentialAccount>{}, second_meter));
  TRY_RESULT(second_stored, persist(second_effects.source_data, "after-retained.boc"));
  TRY_RESULT(final_account, decode_workchain_confidential_account(second_stored));
  if (!final_account.system_pending.empty() || !final_account.pending.empty() ||
      final_account.auth_nonce != 2 || final_account.available_revision != 2)
    return alarm("retained system receipt not consumed exactly once");
  TRY_RESULT(final_value, decrypt(final_account.available, secret, 2000000000));
  TRY_STATUS(assert_balance(final_value, 1999999966));
  TRY_RESULT(free_slot, admit_workchain_deposit(full, key(30), final_account.address, key(4), key(5),
      1000000000, td::make_refint(1003000000), *coordinator.deposit_sequence,
      std::optional<WorkchainConfidentialAccount>{final_account}));
  if (!std::holds_alternative<WorkchainDepositAdmission>(free_slot))
    return alarm("consumed system receipt slot was not released");
  auto second_replay = WorkchainProofTestAccess::create(100000);
  TRY_RESULT(second_independent, execute_workchain_confidential_transfer(env, second_input,
      std::optional<WorkchainConfidentialAccount>{after}, std::optional<WorkchainConfidentialAccount>{}, second_replay));
  if (second_independent.source_data->get_hash() != second_stored->get_hash() ||
      second_replay.consumed() != second_meter.consumed())
    return alarm("retained receipt replay differs");
  std::cout << "retained system COLLECT k=1: available=" << final_value
            << " retained=0 released=yes units=" << second_meter.consumed() << '/' << second_replay.consumed()
            << "; not live block acceptance\n";
  return td::Status::OK();
}
