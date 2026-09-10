#include "block/workchain-registration-proof.h"
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
