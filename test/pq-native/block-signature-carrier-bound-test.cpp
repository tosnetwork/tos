/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "crypto/block/pq-signature-limits.h"

#include "block-signature-carrier-common.h"

namespace {

[[noreturn]] void fail(const char* text) {
  std::fprintf(stderr, "%s\n", text);
  std::exit(1);
}

enum class ExternalVerdict { accepted, oversize, invalid_signature };

template <class Verify>
ExternalVerdict model_byte_gate_before_verifier(td::Slice bytes, Verify&& verify) {
  if (!block::pq::pq_block_signatures_accepts_serialized_size(bytes.size())) {
    return ExternalVerdict::oversize;
  }
  return verify(bytes) ? ExternalVerdict::accepted : ExternalVerdict::invalid_signature;
}

}  // namespace

int main() {
  using namespace block_signature_carrier_test;

  const auto signatures400 = make_signatures(400, false);
  const auto root400 = signature_set_cell(signatures400);
  const auto boc400 = boc(root400);
  if (boc400.size() != 1020996) {
    fail("PROPERTY_A_CANONICAL_SIZE_FAILED: canonical 400-signer BOC size drifted");
  }
  if (!block::pq::pq_block_signatures_accepts_serialized_size(boc400.size())) {
    fail("PROPERTY_A_400_FIT_FAILED: canonical 400-signer BOC does not fit the frozen persisted envelope");
  }

  // The production serializer itself owns the structural count gate.
  const auto signatures401 = make_signatures(401, false);
  const auto rejected401 = try_signature_set_cell(signatures401);
  if (rejected401.is_ok() || block::pq::pq_block_signatures_accepts_signer_count(signatures401.size())) {
    fail("PROPERTY_B_401_REFUSAL_FAILED: production serializer accepted 401 signers");
  }

  // The cell parser enforces the same byte bound before traversing its dictionary.
  // This test-only raw-byte model remains until an external byte parser exists.
  td::BufferSlice hostile(block::pq::pq_block_signatures_hard_max_bytes + 1);
  std::memset(hostile.data(), 0xa5, hostile.size());
  std::size_t verification_calls = 0;
  const auto verdict = model_byte_gate_before_verifier(hostile.as_slice(), [&](td::Slice) {
    ++verification_calls;
    return false;  // malformed ML-DSA bytes would fail if this were reached
  });
  if (verdict != ExternalVerdict::oversize || verification_calls != 0) {
    fail("PROPERTY_C_TEST_MODEL_ORDER_FAILED: test-only size predicate did not run before test-only verifier probe");
  }

  const auto first = boc(root400);
  const auto second = boc(root400);
  if (first.as_slice() != second.as_slice()) {
    fail("PROPERTY_D_DETERMINISTIC_SERIALIZATION_FAILED: identical C++ input produced different BOC bytes");
  }
  td::Bits256 serialized_hash;
  td::sha256(first.as_slice(), serialized_hash.as_slice());
  if (serialized_hash.to_hex() != "0C05E72DD2095B0B3497CEF3422DFBC65B42891BB011C75E769AC245FA0B9B63") {
    fail("PROPERTY_D_DETERMINISTIC_SERIALIZATION_FAILED: canonical 400-signer BOC changed across runs");
  }

  std::printf("BLOCK_SIGNATURE_CARRIER_BOUND_OK hard_max=%zu boc400=%zu headroom=%zu sha256=%s\n",
              block::pq::pq_block_signatures_hard_max_bytes, boc400.size(),
              block::pq::pq_block_signatures_hard_max_bytes - boc400.size(), serialized_hash.to_hex().c_str());
  return 0;
}
