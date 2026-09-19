/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// The exact bytes each post-quantum authorisation signs, as bytes rather than as a field
// list to be rebuilt. Three implementations will construct these independently -- a
// contract, a node and the tooling that signs for an operator -- and a signature made
// over one layout verifies under none of the others.
#include <cstdio>
#include <cstring>
#include <string>

#include "crypto/pq/pq-elector.h"
#include "td/utils/misc.h"

namespace {

td::Bits256 fill(unsigned char b) {
  td::Bits256 out;
  std::memset(out.data(), b, 32);
  return out;
}

void emit(const char* name, const std::string& bytes) {
  std::printf("%s\t%zu\t%s\n", name, bytes.size(), td::hex_encode(td::Slice(bytes)).c_str());
}

}  // namespace

int main() {
  std::printf("# The bytes each post-quantum authorisation signs. Fixed inputs, chosen so every\n");
  std::printf("# field is distinguishable in the output, and a field swapped for another of the\n");
  std::printf("# same width still changes these bytes.\n");
  std::printf("#\n");
  std::printf("# stake:     TAG u32 | global_id i32 | stake_at u32 | max_factor u32 |\n");
  std::printf("#            validator_id u256 | algorithm_id u16 | key_id u256 | adnl_addr u256\n");
  std::printf("# config:    TAG u32 | global_id i32 | validator_set_id u256 | validator_id u256 |\n");
  std::printf("#            idx u16 | proposal_hash u256\n");
  std::printf("# complaint: TAG u32 | global_id i32 | validator_set_id u256 | validator_id u256 |\n");
  std::printf("#            idx u16 | election_id u32 | complaint_hash u256\n");
  std::printf("#\n");
  std::printf("# name\tbytes\thex\n");

  emit("stake", tos::pq::stake_preimage(-239, 1789434000u, 0x10000u, fill(0xa1), 1, fill(0xb2), fill(0xc3)));
  emit("config-vote", tos::pq::config_vote_preimage(-239, fill(0xd4), fill(0xa1), 7, fill(0xe5)));
  emit("complaint-vote", tos::pq::complaint_vote_preimage(-239, fill(0xd4), fill(0xa1), 7, 1789434000u, fill(0xf6)));

  // A second stake that differs from the first in one field only, so a layout that lost
  // that field would produce two identical lines here rather than two different ones.
  emit("stake-other-key", tos::pq::stake_preimage(-239, 1789434000u, 0x10000u, fill(0xa1), 1, fill(0xb3), fill(0xc3)));
  emit("stake-other-validator",
       tos::pq::stake_preimage(-239, 1789434000u, 0x10000u, fill(0xa2), 1, fill(0xb2), fill(0xc3)));
  emit("stake-other-algorithm",
       tos::pq::stake_preimage(-239, 1789434000u, 0x10000u, fill(0xa1), 2, fill(0xb2), fill(0xc3)));
  emit("stake-other-network",
       tos::pq::stake_preimage(-1, 1789434000u, 0x10000u, fill(0xa1), 1, fill(0xb2), fill(0xc3)));
  emit("config-vote-other-set", tos::pq::config_vote_preimage(-239, fill(0xd5), fill(0xa1), 7, fill(0xe5)));
  emit("config-vote-other-index", tos::pq::config_vote_preimage(-239, fill(0xd4), fill(0xa1), 8, fill(0xe5)));
  emit("complaint-vote-other-election",
       tos::pq::complaint_vote_preimage(-239, fill(0xd4), fill(0xa1), 7, 1789434001u, fill(0xf6)));
  return 0;
}
