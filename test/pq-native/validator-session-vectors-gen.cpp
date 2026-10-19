/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Emits the authoritative vectors for consensus session identity. A session id is
// consensus-critical and is computed independently by the node and by tosctl, so the
// member encoding, the serialized group and the resulting id are all recorded here
// and both implementations must reproduce them byte for byte.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "auto/tl/tos_api.hpp"
#include "block/validator-session-members.h"
#include "crypto/pq/pq-consensus.h"
#include "td/utils/misc.h"
#include "tl-utils/tl-utils.hpp"

namespace {

td::Bits256 fill(unsigned char b) {
  td::Bits256 out;
  std::memset(out.data(), b, 32);
  return out;
}

void emit(const char* name, const tos::ValidatorDescr& node) {
  auto members = block::validator_session_members({node});
  auto member_bytes = tos::serialize_tl_object(members[0], true);

  // The same group shape the node builds for a session.
  auto group = tos::create_tl_object<tos::tos_api::validator_groupNew>(0, static_cast<long long>(0x8000000000000000ull),
                                                                       0, 0, 1, td::Bits256::zero(),
                                                                       block::validator_session_members({node}));
  auto group_bytes = tos::serialize_tl_object(group, true);
  auto session_id = tos::get_tl_object_sha_bits256(group);

  // line format: <name> <member_constructor_id> <member_hex> <group_hex> <session_id_hex>
  printf("%s %08x %s %s %s\n", name, members[0]->get_id(), td::hex_encode(member_bytes.as_slice()).c_str(),
         td::hex_encode(group_bytes.as_slice()).c_str(), td::hex_encode(session_id.as_slice()).c_str());
}

}  // namespace

int main() {
  const auto adnl = fill(0xc0);
  auto pq = [&](unsigned char vid, unsigned char kid) {
    return tos::ValidatorDescr{tos::ValidatorId{fill(vid)},
                               1,
                               tos::ConsensusKeyId{fill(kid)},
                               std::string(tos::pq::mldsa44_public_key_bytes, '\x01'),
                               5,
                               adnl};
  };
  emit("classical", tos::ValidatorDescr{tos::Ed25519_PublicKey{fill(0x11)}, 5, adnl});
  emit("pq-a-key1", pq(0xa0, 0xb0));
  emit("pq-a-key2", pq(0xa0, 0xb1));
  return 0;
}
