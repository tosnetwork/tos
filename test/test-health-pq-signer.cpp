#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <string>

#include "crypto/pq/consensus-pq-signer.h"
#include "crypto/pq/mldsa44.h"
#include "metrics/core-health.h"
int main() {
  auto key = tos::pq::ValidatorPQKeyStore::from_seed(std::string(32, '\x42'));
  assert(key.has_value());
  auto before = tos::health::pq_sign.completed.load();
  tos::health::enabled.store(false);
  auto disabled = key->sign_consensus("health fixture disabled");
  assert(disabled.has_value());
  assert(tos::health::pq_sign.completed.load() == before);
  tos::health::enabled.store(true);
  auto signature = key->sign_consensus("health fixture enabled");
  assert(signature.has_value());
  assert(tos::health::pq_sign.completed.load() == before + 1);
  assert(tos::health::pq_sign.failed.load() == 0);
  std::uint64_t count = 0;
  for (const auto &bucket : tos::health::pq_sign.buckets[0]) {
    count += bucket.load();
  }
  assert(count == 1);
  assert(tos::pq::verify_mldsa44("health fixture enabled", tos::pq::simplex_sign_context, signature->signature,
                                 key->consensus_key().public_key) == tos::pq::VerifyResult::valid);
  auto invalid = key->sign_consensus(std::string(tos::pq::mldsa44_max_message_bytes + 1, 'x'));
  assert(!invalid.has_value());
  assert(tos::health::pq_sign.completed.load() == before + 1);
  assert(tos::health::pq_sign.failed.load() == 1);
}
