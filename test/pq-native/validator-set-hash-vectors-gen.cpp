/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Emits the authoritative vectors for the version 2 validator-set commitment.
// Both the exact preimage and the resulting hash are recorded, so the two
// implementations are compared byte for byte and not only by result.
#include <cstdio>
#include <string>
#include <vector>

#include "block/block.h"
#include "crypto/pq/pq-consensus.h"
#include "td/utils/crypto.h"
#include "td/utils/misc.h"

namespace {

td::Bits256 fill(unsigned char b) {
  td::Bits256 out;
  std::memset(out.data(), b, 32);
  return out;
}

// Identities are given explicitly so a case can rotate the key identity while
// holding the membership identity fixed, which is the property under test.
tos::ValidatorDescr descr(unsigned char vid, unsigned char kid, td::uint64 weight, unsigned char adnl) {
  return tos::ValidatorDescr{tos::ValidatorId{fill(vid)},
                             1,
                             tos::ConsensusKeyId{fill(kid)},
                             std::string(tos::pq::mldsa44_public_key_bytes, '\x01'),
                             weight,
                             fill(adnl)};
}

void emit(const char* name, tos::CatchainSeqno cc_seqno, const std::vector<tos::ValidatorDescr>& nodes) {
  auto preimage = block::validator_set_hash_preimage(cc_seqno, nodes);
  auto hash = block::compute_validator_set_hash(cc_seqno, tos::ShardIdFull{tos::masterchainId}, nodes);
  // The descriptor fields are recorded too, so the other implementation rebuilds the
  // same inputs rather than being handed the answer.
  std::string fields;
  for (const auto& n : nodes) {
    if (!fields.empty()) {
      fields += ";";
    }
    fields += td::hex_encode(n.validator_id.value.as_slice()) + ":" + td::hex_encode(n.key_id.value.as_slice()) + ":" +
              std::to_string(n.weight) + ":" + td::hex_encode(n.addr.as_slice());
  }
  printf("%s %u %s %s %08x\n", name, (unsigned)cc_seqno, fields.c_str(), td::hex_encode(td::Slice(preimage)).c_str(),
         hash);
}

}  // namespace

int main() {
  // line format: <name> <cc_seqno> <preimage_hex> <hash_hex>
  emit("single", 1, {descr(0xa0, 0xb0, 5, 0xc0)});
  // same membership identity, rotated key identity
  emit("rotated", 1, {descr(0xa0, 0xb1, 5, 0xc0)});
  emit("two", 7, {descr(0xa0, 0xb0, 5, 0xc0), descr(0xa1, 0xb2, 9, 0xc1)});
  emit("zero-adnl", 0, {descr(0xa0, 0xb0, 1, 0x00)});
  emit("max-weight", 4294967295u, {descr(0xff, 0x00, 18446744073709551615ull, 0x7f)});
  return 0;
}
