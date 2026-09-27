/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#ifdef NDEBUG
#undef NDEBUG  // test assertions must stay live even in Release (-DNDEBUG)
#endif
#include <cassert>
#include <cstdio>
#include <string>

#include "block/pq-vote.h"
#include "pq/mldsa44.h"
#include "vm/cellslice.h"

using block::pq::complaint_vote_body;
using block::pq::config_vote_body;
using block::pq::parse_vote_subject;
using block::pq::vote_query_id;

namespace {

td::Bits256 must_parse(td::Slice text) {
  auto r = parse_vote_subject(text);
  assert(r.is_ok());
  return r.move_as_ok();
}

void refuses(td::Slice text, const char* why) {
  auto r = parse_vote_subject(text);
  if (r.is_ok()) {
    std::printf("accepted a subject it must refuse (%s): %s\n", why, text.str().c_str());
    assert(false);
  }
}

// What an operator types is the whole subject or it is nothing. A partially parsed hash
// is a vote on something else, cast with this validator's authority.
void a_subject_is_the_whole_text() {
  auto all_ones = must_parse("0x" + std::string(64, 'f'));
  for (int i = 0; i < 32; i++) {
    assert(all_ones.data()[i] == 0xff);
  }

  // The same number written both ways is the same subject.
  assert(must_parse("0x10203040") == must_parse("270544960"));

  // A short hash is left-padded, not truncated or shifted.
  auto small = must_parse("0x2a");
  for (int i = 0; i < 31; i++) {
    assert(small.data()[i] == 0);
  }
  assert(small.data()[31] == 0x2a);

  refuses("", "empty");
  refuses("0x", "a prefix and nothing else");
  refuses("0x10203040 ", "trailing space");
  refuses("10203040abc", "decimal digits followed by letters");
  refuses("0xdeadbeefzz", "hex digits followed by letters");
  refuses("-1", "negative");
  refuses("0x1" + std::string(64, '0'), "one bit past 256");
  // Decimal 2^256 exactly.
  refuses("115792089237316195423570985008687907853269984665640564039457584007913129639936", "2^256 in decimal");
  // 2^256 - 1 is the last subject that exists.
  assert(must_parse("115792089237316195423570985008687907853269984665640564039457584007913129639935") ==
         must_parse("0x" + std::string(64, 'f')));
}

// The identifier carries the low 32 bits of the subject, so two votes cast in the same
// second on different proposals are still told apart.
void the_query_id_names_the_second_and_the_subject() {
  auto a = must_parse("0x10203040");
  auto b = must_parse("0x10203041");
  assert(vote_query_id(1789859739, a) == (static_cast<td::uint64>(1789859739) << 32 | 0x10203040ull));
  assert(vote_query_id(1789859739, a) != vote_query_id(1789859739, b));
  assert(vote_query_id(1789859739, a) != vote_query_id(1789859740, a));
}

// The two bodies differ in their operation and in what they name, and neither carries
// the signature inline -- the verifying instruction takes a byte chain behind a
// reference, and 2420 bytes do not fit in a cell beside anything else.
void the_two_bodies_are_distinct_and_carry_the_signature_behind_a_reference() {
  auto subject = must_parse("0x20304050");
  std::string signature(tos::pq::mldsa44_signature_bytes, '\x5a');

  auto config = config_vote_body(7, 9, subject, signature);
  assert(config.is_ok());
  auto complaint = complaint_vote_body(7, 9, 0x89abcdef, subject, signature);
  assert(complaint.is_ok());

  auto config_root = config.move_as_ok();
  auto complaint_root = complaint.move_as_ok();
  assert(config_root->get_hash() != complaint_root->get_hash());

  vm::CellSlice cs{vm::NoVm(), config_root};
  assert(cs.fetch_ulong(32) == tos::pq::config_pq_vote_op);
  assert(cs.fetch_ulong(64) == 7);
  assert(cs.fetch_ulong(16) == 9);
  td::Bits256 read_back;
  assert(cs.fetch_bits_to(read_back.bits(), 256));
  assert(read_back == subject);
  assert(cs.size() == 0);
  assert(cs.size_refs() == 1);

  vm::CellSlice cc{vm::NoVm(), complaint_root};
  assert(cc.fetch_ulong(32) == tos::pq::elector_pq_complaint_op);
  assert(cc.fetch_ulong(64) == 7);
  assert(cc.fetch_ulong(16) == 9);
  assert(cc.fetch_ulong(32) == 0x89abcdef);
  assert(cc.fetch_bits_to(read_back.bits(), 256));
  assert(read_back == subject);
  assert(cc.size() == 0);
  assert(cc.size_refs() == 1);

  // A signature that is not the suite's length is not a signature.
  assert(config_vote_body(7, 9, subject, signature.substr(1)).is_error());
  assert(complaint_vote_body(7, 9, 1, subject, signature.substr(1)).is_error());
}

}  // namespace

int main() {
  a_subject_is_the_whole_text();
  the_query_id_names_the_second_and_the_subject();
  the_two_bodies_are_distinct_and_carry_the_signature_behind_a_reference();
  std::printf("vote-body: ok\n");
  return 0;
}
