/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// Block finality signatures: the post-quantum BlockSignatures a block proof or a peer
// carries, parsed from a cell (BlockSignatureSet::fetch, with and without the trusted
// validator set) and verified as final and as approval against the trusted context
// (verify_pq_finality).
//
// The input is a bag of cells whose root is the signature set. The trusted context is the
// one the shared block-signature tests use: four validators with post-quantum keys from
// fixed public seeds and weights 4, 3, 2, 1.
//
// A set accepted against the trusted validator set is also accepted without it. A set that
// verifies carries at least the quorum weight of the set, and serialized again from what
// was parsed it is the same cell.
//
// Run:
//   build-fuzz/fuzz/fuzz-finality-signatures -max_total_time=300 -max_len=65536 fuzz-work/fuzz-finality-signatures test/fuzz/corpus/fuzz-finality-signatures

#include "test/pq-native/pq-block-signature-test-common.h"
#include "vm/boc.h"

#include "fuzz-common.h"

namespace {

const pq_block_signature_test::Fixture *fixture = nullptr;

void check_verified(const block::BlockSignatureSet &set, tos::ValidatorWeight weight) {
  TOS_FUZZ_INVARIANT(weight >= tos::quorum_threshold(fixture->validator_set->get_total_weight()));
  TOS_FUZZ_INVARIANT(set.is_pq());
  auto r_signatures = set.export_pq_signatures();
  auto r_session = set.pq_session_id();
  auto r_slot = set.pq_slot();
  auto r_candidate = set.pq_candidate_data();
  TOS_FUZZ_INVARIANT(r_signatures.is_ok() && r_session.is_ok() && r_slot.is_ok() && r_candidate.is_ok());
  TOS_FUZZ_INVARIANT(r_session.ok() == fixture->session);
}

}  // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  tos::fuzz::quiet_logging();
  static const pq_block_signature_test::Fixture instance;
  fixture = &instance;
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  auto r_root = vm::std_boc_deserialize(td::Slice(reinterpret_cast<const char *>(data), size));
  if (r_root.is_error()) {
    return 0;
  }
  auto root = r_root.move_as_ok();

  tos::ValidatorWeight claimed_weight = 0;
  auto r_untrusted = block::BlockSignatureSet::fetch(root, claimed_weight);
  auto r_trusted = block::BlockSignatureSet::fetch(root, fixture->validator_set);
  if (r_trusted.is_error()) {
    return 0;
  }
  TOS_FUZZ_INVARIANT(r_untrusted.is_ok());
  auto set = r_trusted.move_as_ok();

  const block::PQFinalityVerificationContext context{fixture->validator_set, fixture->id, fixture->session};
  auto r_final = block::verify_pq_finality(context, *set, block::FinalityRole::Final);
  if (r_final.is_ok()) {
    check_verified(*set, r_final.ok());
  }
  auto r_approve = block::verify_pq_finality(context, *set, block::FinalityRole::Approve);
  if (r_approve.is_ok()) {
    check_verified(*set, r_approve.ok());
  }
  // One set is never both a finalization and an approval.
  TOS_FUZZ_INVARIANT(!(r_final.is_ok() && r_approve.is_ok()));

  if (set->is_pq()) {
    auto r_signatures = set->export_pq_signatures();
    auto r_session = set->pq_session_id();
    auto r_slot = set->pq_slot();
    auto r_candidate_data = set->pq_candidate_data();
    if (r_signatures.is_ok() && r_session.is_ok() && r_slot.is_ok() && r_candidate_data.is_ok()) {
      auto r_candidate =
          tos::fetch_tl_object<tos::tos_api::consensus_CandidateHashData>(r_candidate_data.ok().as_slice(), true);
      if (r_candidate.is_ok() && set->is_final()) {
        auto r_cell = block::BlockSignatureSet::serialize_simplex_pq(r_signatures.ok(), set->get_catchain_seqno(),
                                                                     set->get_validator_set_hash(), claimed_weight,
                                                                     r_session.ok(), r_slot.ok(), r_candidate.ok());
        TOS_FUZZ_INVARIANT(r_cell.is_ok());
        TOS_FUZZ_INVARIANT(r_cell.ok()->get_hash() == root->get_hash());
      }
    }
  }
  return 0;
}
