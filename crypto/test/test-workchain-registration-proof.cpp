#include "block/workchain-registration-proof.h"
#include "block/workchain-registration.h"
#include "block/workchain-registration-payment.h"
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
  // Actual Native final-import acquisition: message value is consumed once,
  // while the coordinator gains the same value and locks it in the sub-bucket.
  block::WorkchainResourcePolicy resources{4, {64,4096,8,16,16,5},
      {256,16384,128,8192,64}, {32,128,8192,256,16384,16}, {0,2,2},1};
  auto config=block::encode_workchain_engine_parameters({400,policy.instance,resources,
      vm::CellBuilder().finalize(),10});
  ASSERT_TRUE(config.is_ok());
  block::WorkchainNativeIngressPolicy ingress;
  ingress.workchain_id=2; ingress.engine_key={block::WorkchainFormat::Basic,0x554e4f32};
  ingress.vm_mode=17; ingress.descriptor_version=2;
  ingress.executor_address=fill(9); ingress.engine_configuration=config.ok();
  block::WorkchainExecutionDescriptor descriptor;
  descriptor.workchain_id=2; descriptor.active=true; descriptor.vm_version=0x554e4f32;
  descriptor.vm_mode=17; descriptor.version=2;
  auto envelope_for=[&](long long amount,const td::Bits256& sender,const td::Bits256& recipient) {
    vm::CellBuilder cb;
    cb.store_long(4,4).store_long(4,3).store_long(0,8).store_bits(sender.bits(),256)
      .store_long(4,3).store_long(2,8).store_bits(recipient.bits(),256);
    ASSERT_TRUE(block::CurrencyCollection(amount).store(cb));
    // ihr_fee=0, fwd_fee=0, created_lt/time, absent init, body by reference.
    cb.store_long(0,4).store_long(0,4).store_long(1,64).store_long(1,32)
      .store_long(0,1).store_long(1,1).store_ref(cell.ok());
    auto message=cb.finalize();
    block::tlb::MsgEnvelope::Record_std rec{0x60,0x60,td::make_refint(0),message,{},{}};
    td::Ref<vm::Cell> envelope;
    ASSERT_TRUE(tlb::pack_cell(envelope,rec));
    return std::make_pair(envelope,td::Bits256(message->get_hash().bits()));
  };
  auto payment=envelope_for(10,fill(8),ingress.executor_address);
  td::Result<block::WorkchainNativeInboxPlan> inbox{block::WorkchainNativeInboxPlan{{payment.first},1}};
  auto acquire=[&](const td::Result<block::WorkchainNativeInboxPlan>& messages,const td::Bits256& hash) {
    return block::execute_workchain_registration_payment(policy,ingress,descriptor,messages,hash,
        old.coordinator,block::CurrencyCollection(50),{},proof);
  };
  auto paid=acquire(inbox,payment.second);
  if (paid.is_error()) LOG(ERROR) << paid.error();
  ASSERT_TRUE(paid.is_ok());
  ASSERT_EQ(paid.ok().registration.payer_balance,0u);
  ASSERT_TRUE(paid.ok().coordinator_flow.old_balance==block::CurrencyCollection(50));
  ASSERT_TRUE(paid.ok().coordinator_flow.imported==block::CurrencyCollection(10));
  ASSERT_TRUE(paid.ok().coordinator_flow.new_balance==block::CurrencyCollection(60));
  ASSERT_TRUE(paid.ok().coordinator_flow.fees.is_zero());
  ASSERT_EQ(block::decode_workchain_coordinator_state(paid.ok().registration.coordinator_data)
      .move_as_ok().refundable_deposits,10u);
  auto wrong=envelope_for(9,fill(8),ingress.executor_address);
  td::Result<block::WorkchainNativeInboxPlan> too_small{block::WorkchainNativeInboxPlan{{wrong.first},1}};
  auto underpaid=acquire(too_small,wrong.second);
  ASSERT_TRUE(underpaid.is_error()); ASSERT_EQ(underpaid.error().code(),-7200);
  wrong=envelope_for(10,fill(7),ingress.executor_address);
  td::Result<block::WorkchainNativeInboxPlan> wrong_sender{block::WorkchainNativeInboxPlan{{wrong.first},1}};
  auto unauthorized=acquire(wrong_sender,wrong.second);
  ASSERT_TRUE(unauthorized.is_error()); ASSERT_EQ(unauthorized.error().code(),-7200);
  td::Result<block::WorkchainNativeInboxPlan> duplicate_payment{block::WorkchainNativeInboxPlan{{payment.first,payment.first},1}};
  ASSERT_EQ(acquire(duplicate_payment,payment.second).error().code(),-7200);
  td::Result<block::WorkchainNativeInboxPlan> unavailable_payment{td::Status::Error("queue proof unavailable")};
  ASSERT_EQ(acquire(unavailable_payment,payment.second).error().code(),-7201);
  ASSERT_EQ(acquire(inbox,fill(0)).error().code(),-7200);
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
