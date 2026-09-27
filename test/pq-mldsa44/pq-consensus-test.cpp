#include "pq-consensus.h"
#ifdef NDEBUG
#undef NDEBUG  // test assertions must stay live even in Release (-DNDEBUG)
#endif
#include <cassert>
#include <cstdio>
#include <limits>
using namespace tos::pq;
int main() {
  std::string pk(mldsa44_public_key_bytes, '\x01'), sig(mldsa44_signature_bytes, '\x02');
  // size controls: 1311/1312/1313 and 2419/2420/2421
  assert(!valid_public_key(PQAlgorithmId::mldsa44, std::string(1311, 'x')));
  assert(valid_public_key(PQAlgorithmId::mldsa44, pk));
  assert(!valid_public_key(PQAlgorithmId::mldsa44, std::string(1313, 'x')));
  assert(!valid_signature(PQAlgorithmId::mldsa44, std::string(2419, 'x')));
  assert(valid_signature(PQAlgorithmId::mldsa44, sig));
  assert(!valid_signature(PQAlgorithmId::mldsa44, std::string(2421, 'x')));
  // unknown algorithm fails closed
  assert(!valid_public_key(PQAlgorithmId::unknown, pk));
  assert(!valid_signature(PQAlgorithmId::unknown, sig));
  assert(!is_admitted(PQAlgorithmId::unknown) && is_admitted(PQAlgorithmId::mldsa44));

  // key_id: deterministic and key-dependent
  auto a = derive_key_id(PQAlgorithmId::mldsa44, pk);
  auto b = derive_key_id(PQAlgorithmId::mldsa44, pk);
  assert(a.has_value() && b.has_value() && *a == *b);
  std::string pk2 = pk;
  pk2[0] ^= 1;
  assert(derive_key_id(PQAlgorithmId::mldsa44, pk2) != a);  // different key -> different id

  // key_id fails closed: an unadmitted algorithm or a wrong-length key yields NO id.
  // An unknown suite must never be able to acquire a usable consensus identity.
  assert(!derive_key_id(PQAlgorithmId::unknown, pk).has_value());
  assert(!derive_key_id(PQAlgorithmId::mldsa44, std::string(1311, 'x')).has_value());
  assert(!derive_key_id(PQAlgorithmId::mldsa44, std::string(1313, 'x')).has_value());
  assert(!derive_key_id(PQAlgorithmId::mldsa44, std::string()).has_value());

  // Exact derivation vector. The preimage is fully specified and the hash is plain
  // SHA-256, so any independent implementation must reproduce this byte for byte:
  //   SHA-256("TOS-PQ-CONSENSUS-KEY-v1" || u16_le(1) || 0x01 * 1312)
  // This locks the domain string AND the little-endian algorithm-id encoding.
  const std::array<std::uint8_t, 32> expect_key_id{0xab, 0xf4, 0xe6, 0xdd, 0xe7, 0x10, 0x7b, 0x53, 0xa4, 0x8a, 0xb9,
                                                   0xb7, 0x0f, 0xc3, 0x94, 0x22, 0x45, 0x14, 0x6d, 0x9e, 0x37, 0x47,
                                                   0xeb, 0x2f, 0x5f, 0x1a, 0xa7, 0x34, 0xb0, 0x4e, 0x14, 0x11};
  assert(*a == expect_key_id);

  // the four frozen signature contexts are distinct and exactly as specified
  assert(key_id_domain == "TOS-PQ-CONSENSUS-KEY-v1");
  assert(simplex_sign_context == "TOS-CONSENSUS-SIMPLEX-v1");
  assert(validator_election_context == "TOS-VALIDATOR-ELECTION-v1");
  assert(validator_config_vote_context == "TOS-VALIDATOR-CONFIG-VOTE-v1");
  assert(config_admin_context == "TOS-CONFIG-ADMIN-v1");

  // limits: provisional sizing only, monotone, and saturating instead of overflowing
  PQConsensusLimits L;
  assert(L.public_key_bytes == 1312 && L.signature_bytes == 2420);
  assert(L.estimated_certificate_bytes(100) < L.estimated_certificate_bytes(400));
  assert(L.estimated_max_certificate_bytes() == L.estimated_certificate_bytes(400));
  assert(L.estimated_certificate_bytes(std::numeric_limits<std::size_t>::max()) ==
         std::numeric_limits<std::size_t>::max());  // saturates, never wraps
  assert(L.estimated_certificate_bytes(0) == 0);

  printf("PQ_CONSENSUS_FOUNDATION_OK cert100=%zu cert400=%zu key_id0=%02x\n", L.estimated_certificate_bytes(100),
         L.estimated_certificate_bytes(400), (*a)[0]);
  return 0;
}
