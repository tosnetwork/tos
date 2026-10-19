/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// The message a validator's vote travels in, as bytes rather than as a field list to be
// rebuilt.
//
// The preimage vectors beside this file hold what is signed. These hold what carries it:
// the operation, the identifier, what is being voted on, and the signature behind a
// reference. Three implementations build this cell -- the node, the operator tooling and,
// read from the other side, the contract -- and a vote built to one layout is refused by
// a contract reading another, with the sender charged for the message.
//
// The signature is a fixed pattern rather than a real one. Nothing here verifies; the
// point is the shape the bytes arrive in.
#include <cstdio>
#include <cstring>
#include <string>

#include "crypto/block/pq-vote.h"
#include "crypto/pq/mldsa44.h"
#include "td/utils/misc.h"
#include "vm/boc.h"

namespace {

td::Bits256 fill(unsigned char b) {
  td::Bits256 out;
  std::memset(out.data(), b, 32);
  return out;
}

std::string pattern_signature() {
  std::string out(tos::pq::mldsa44_signature_bytes, '\0');
  for (std::size_t i = 0; i < out.size(); i++) {
    out[i] = static_cast<char>(i % 251);
  }
  return out;
}

void emit(const char* name, td::Result<td::Ref<vm::Cell>> body) {
  auto cell = body.move_as_ok();
  auto boc = vm::std_boc_serialize(cell, 2).move_as_ok();
  std::printf("%s\t%s\t%s\n", name, cell->get_hash().to_hex().c_str(), td::hex_encode(boc.as_slice()).c_str());
}

}  // namespace

int main() {
  const auto signature = pattern_signature();

  std::printf("# The cells a validator's vote travels in. Fixed inputs, chosen so every field is\n");
  std::printf("# distinguishable, and a field swapped for another of the same width still changes\n");
  std::printf("# the root hash.\n");
  std::printf("#\n");
  std::printf("# config:    PQvo u32 | query_id u64 | idx u16 | proposal_hash u256  + ref(signature)\n");
  std::printf("# complaint: PQco u32 | query_id u64 | idx u16 | election_id u32 |\n");
  std::printf("#            complaint_hash u256                                    + ref(signature)\n");
  std::printf("#\n");
  std::printf("# The signature is the byte i %% 251 repeated to the suite's 2420 bytes.\n");
  std::printf("#\n");
  std::printf("# name\troot_hash\tboc_hex\n");

  emit("config-vote", block::pq::config_vote_body(0x1234567890abcdefULL, 7, fill(0xe5), signature));
  emit("complaint-vote", block::pq::complaint_vote_body(0x1234567890abcdefULL, 7, 1789434000u, fill(0xf6), signature));

  // Each of these differs from the one above in exactly one field, so a layout that
  // dropped that field would repeat a line here rather than produce a new one.
  emit("config-vote-other-query", block::pq::config_vote_body(0x1234567890abcdeeULL, 7, fill(0xe5), signature));
  emit("config-vote-other-index", block::pq::config_vote_body(0x1234567890abcdefULL, 8, fill(0xe5), signature));
  emit("config-vote-other-proposal", block::pq::config_vote_body(0x1234567890abcdefULL, 7, fill(0xe6), signature));
  emit("complaint-vote-other-index",
       block::pq::complaint_vote_body(0x1234567890abcdefULL, 8, 1789434000u, fill(0xf6), signature));
  emit("complaint-vote-other-election",
       block::pq::complaint_vote_body(0x1234567890abcdefULL, 7, 1789434001u, fill(0xf6), signature));
  emit("complaint-vote-other-complaint",
       block::pq::complaint_vote_body(0x1234567890abcdefULL, 7, 1789434000u, fill(0xf7), signature));
  return 0;
}
