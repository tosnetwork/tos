#include "block/workchain-registration-proof.h"
#include "block/workchain-registration.h"
#include "td/utils/tests.h"
#include "td/utils/misc.h"
#include <algorithm>

TEST(RegistrationProof, RustPossessionVectorAndHostBinding) {
  // Same public vector as key_possession.rs: test-only s=71, k=93.
  auto fill = [](unsigned char byte) {
    td::Bits256 value;
    std::fill(value.as_slice().begin(), value.as_slice().end(), byte);
    return value;
  };
  block::WorkchainConfidentialAccount a{};
  a.global_id = -23903;
  a.genesis_hash = fill(1);
  a.address = {2, fill(2), fill(3)};
  a.bindings = {fill(4), fill(5), fill(6)};
  a.schema_version = 1;
  a.relation_profile = 1;
  a.proof_profile = 2;
  a.key_epoch = 0;
  auto key = td::hex_decode("da6b841f2b72c6d5e15bd974905e1e218b1aa5c4eb4da5ea34bfeebab76dbf25");
  ASSERT_TRUE(key.is_ok());
  a.public_key.as_slice().copy_from(key.ok());
  auto encoded = td::hex_decode("a226f594e835391bcb4b5e737dc2e7f797679527a174cc45d28effc268b3b401"
                                "5a8ca3eec3f957d51d7b9c5754f7fbf2e9b92282c8ce0961c8fb1f160a102402");
  ASSERT_TRUE(encoded.is_ok());
  std::array<unsigned char, 64> proof;
  std::copy(encoded.ok().begin(), encoded.ok().end(), proof.begin());
  auto result = block::verify_workchain_registration_possession(a, proof);
#if defined(TOS_CONFIDENTIAL_PROOF_BACKEND_LINKED)
  ASSERT_TRUE(result.is_ok());
  a.funding = {10, 0, fill(8)};
  a.available = {fill(0), fill(0)};
  a.auth_nonce = 0;
  a.available_revision = 0;
  a.lifecycle = block::WorkchainAccountActive{};
  auto cell = block::encode_workchain_confidential_account(a);
  ASSERT_TRUE(cell.is_ok());
  block::WorkchainRegistrationPolicy policy{a.global_id, a.genesis_hash, a.address.instance,
      a.bindings, 1, 1, 2, 10};
  block::WorkchainRegistrationSnapshot old{{2, {1, 1000000, 0, 0}, 0}, {}, 0, fill(8), 100};
  auto registered = block::execute_workchain_registration(policy, old, a.address.account, cell.ok(), proof);
  ASSERT_TRUE(registered.is_ok());
  ASSERT_EQ(registered.ok().payer_balance, 90u);
  auto coordinator = block::decode_workchain_coordinator_state(registered.ok().coordinator_data);
  ASSERT_TRUE(coordinator.is_ok());
  ASSERT_EQ(coordinator.ok().system.registered_accounts, 1u);
  ASSERT_EQ(coordinator.ok().refundable_deposits, 10u);
  ASSERT_EQ(old.payer_balance, 100u);
  ASSERT_EQ(old.coordinator.system.registered_accounts, 0u);
  ASSERT_EQ(old.coordinator.refundable_deposits, 0u);
  auto replay_old = old;
  replay_old.existing_account = registered.ok().account_data;
  auto duplicate = block::execute_workchain_registration(policy, replay_old, a.address.account, cell.ok(), proof);
  ASSERT_TRUE(duplicate.is_error());
  ASSERT_EQ(duplicate.error().code(), static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
  auto wrong_address = block::execute_workchain_registration(policy, old, fill(9), cell.ok(), proof);
  ASSERT_TRUE(wrong_address.is_error());
  ASSERT_EQ(wrong_address.error().code(), static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
  auto poor = old;
  poor.payer_balance = 9;
  ASSERT_TRUE(block::execute_workchain_registration(policy, poor, a.address.account, cell.ok(), proof).is_error());
  ASSERT_EQ(poor.payer_balance, 9u);
  auto exhausted = old;
  exhausted.coordinator.refundable_deposits = UINT64_MAX;
  ASSERT_TRUE(block::execute_workchain_registration(policy, exhausted, a.address.account, cell.ok(), proof).is_error());
  exhausted = old;
  exhausted.coordinator.system.registered_accounts = UINT64_MAX;
  ASSERT_TRUE(block::execute_workchain_registration(policy, exhausted, a.address.account, cell.ok(), proof).is_error());
  auto bad_proof = proof;
  bad_proof[32] ^= 1;
  auto denied = block::execute_workchain_registration(policy, old, a.address.account, cell.ok(), bad_proof);
  ASSERT_TRUE(denied.is_error());
  ASSERT_EQ(denied.error().code(), static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
  ASSERT_EQ(old.payer_balance, 100u);
  ASSERT_TRUE(old.existing_account.is_null());
  a.key_epoch = 1;
  result = block::verify_workchain_registration_possession(a, proof);
  ASSERT_TRUE(result.is_error());
  ASSERT_EQ(result.code(), static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
  a.key_epoch = 0;
  proof[32] ^= 1;
  result = block::verify_workchain_registration_possession(a, proof);
  ASSERT_TRUE(result.is_error());
  ASSERT_EQ(result.code(), static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
#else
  ASSERT_TRUE(result.is_error());
  ASSERT_EQ(result.code(), static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
#endif
}
