/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <functional>

#include "pq/mldsa44.h"
#include "vm/cellslice.h"

#include "pq-vote.h"

namespace block::pq {
namespace {

// Both bodies have the same shape: the operation, a query id, what is being voted on,
// and the signature behind a reference. Written once so the two cannot drift.
td::Result<td::Ref<vm::Cell>> vote_body(td::uint32 op, td::uint64 query_id,
                                        const std::function<bool(vm::CellBuilder&)>& subject, td::Slice signature) {
  // Exactly the suite's length. The packer takes a ceiling, so a short signature would
  // otherwise encode into a well-formed vote that only the verifying instruction, on
  // the chain, would find to be nothing.
  if (signature.size() != tos::pq::mldsa44_signature_bytes) {
    return td::Status::Error("a validator vote carries an ML-DSA-44 signature of exactly 2420 bytes");
  }
  TRY_RESULT(packed, tos::pq::pack_pq_bytes(signature, tos::pq::mldsa44_signature_bytes));
  vm::CellBuilder cb;
  if (!(cb.store_long_bool(op, 32) && cb.store_long_bool(query_id, 64) && subject(cb) &&
        cb.store_ref_bool(std::move(packed)))) {
    return td::Status::Error("a validator vote does not fit in one cell");
  }
  return cb.finalize();
}

}  // namespace

td::Result<td::Bits256> parse_vote_subject(td::Slice text) {
  int base = 10;
  if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
    base = 16;
    text.remove_prefix(2);
  }
  if (text.empty()) {
    return td::Status::Error("the hash to vote on is empty");
  }
  td::BigInt256 value;
  auto consumed = base == 16 ? value.parse_hex(text.data(), static_cast<int>(text.size()))
                             : value.parse_dec(text.data(), static_cast<int>(text.size()));
  if (consumed != static_cast<int>(text.size()) || !value.is_valid()) {
    return td::Status::Error("the hash to vote on is not a number");
  }
  // Unsigned export into 32 bytes is what bounds the subject: it refuses a negative
  // value and anything past 256 bits. A separate range check ahead of it would be a
  // guard no input could reach, and so a guard no test could hold.
  td::Bits256 hash;
  if (!value.export_bytes(hash.data(), 32, false)) {
    return td::Status::Error("the hash to vote on is negative or does not fit in 256 bits");
  }
  return hash;
}

td::uint64 vote_query_id(td::uint32 now, const td::Bits256& subject) {
  td::uint32 low = 0;
  for (int i = 28; i < 32; i++) {
    low = (low << 8) | subject.data()[i];
  }
  return (static_cast<td::uint64>(now) << 32) | low;
}

td::Result<td::Ref<vm::Cell>> config_vote_body(td::uint64 query_id, td::uint16 idx, const td::Bits256& proposal_hash,
                                               td::Slice signature) {
  return vote_body(
      tos::pq::config_pq_vote_op, query_id,
      [&](vm::CellBuilder& cb) {
        return cb.store_long_bool(idx, 16) && cb.store_bits_bool(proposal_hash.cbits(), 256);
      },
      signature);
}

td::Result<td::Ref<vm::Cell>> complaint_vote_body(td::uint64 query_id, td::uint16 idx, td::uint32 election_id,
                                                  const td::Bits256& complaint_hash, td::Slice signature) {
  return vote_body(
      tos::pq::elector_pq_complaint_op, query_id,
      [&](vm::CellBuilder& cb) {
        return cb.store_long_bool(idx, 16) && cb.store_long_bool(election_id, 32) &&
               cb.store_bits_bool(complaint_hash.cbits(), 256);
      },
      signature);
}

}  // namespace block::pq
