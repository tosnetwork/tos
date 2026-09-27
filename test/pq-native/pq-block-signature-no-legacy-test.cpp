/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cstdio>

#include "crypto/block/block-auto.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellString.h"

#include "pq-block-signature-test-common.h"

namespace {

using namespace pq_block_signature_test;

td::Ref<vm::Cell> legacy_cell(unsigned tag, const Fixture& fixture) {
  vm::CellBuilder root;
  if (!(root.store_long_bool(tag, 8) && root.store_long_bool(fixture.validator_set->get_validator_set_hash(), 32) &&
        root.store_long_bool(Fixture::catchain_seqno, 32) && root.store_long_bool(0, 32) &&
        root.store_long_bool(0, 64) && root.store_bool_bool(false))) {
    fail("PQ_BLOCK_SIGNATURE_LEGACY_FIXTURE_FAILED");
  }
  if (tag == 0x12) {
    root.store_bits(fixture.session.cbits(), 256);
    root.store_long(Fixture::slot, 32);
    auto candidate_bytes = tos::serialize_tl_object(candidate(fixture.id), true);
    auto candidate_cell = vm::CellString::create(candidate_bytes.as_slice());
    if (candidate_cell.is_error()) {
      fail("PQ_BLOCK_SIGNATURE_LEGACY_CANDIDATE_FAILED");
    }
    root.store_ref(candidate_cell.move_as_ok());
  }
  return root.finalize_novm();
}

void expect_legacy_refusal(td::Ref<block::BlockSignatureSet> signatures, const Fixture& fixture,
                           std::string_view name) {
  expect_error(signatures->check_signatures(fixture.validator_set, fixture.id),
               "unsupported carrier for post-quantum validator set", name);
}

}  // namespace

int main() {
  Fixture fixture;

  expect_error(block::BlockSignatureSet::fetch(legacy_cell(0x11, fixture), fixture.validator_set),
               "unsupported carrier for post-quantum validator set", "cell-ordinary-under-pq-set");
  expect_error(block::BlockSignatureSet::fetch(legacy_cell(0x12, fixture), fixture.validator_set),
               "unsupported carrier for post-quantum validator set", "cell-simplex-under-pq-set");

  auto node_ordinary = tos::create_tl_object<tos::tos_api::tosNode_signatureSet_ordinary>();
  node_ordinary->cc_seqno_ = Fixture::catchain_seqno;
  node_ordinary->validator_set_hash_ = fixture.validator_set->get_validator_set_hash();
  expect_legacy_refusal(
      block::BlockSignatureSet::fetch(tos::tl_object_ptr<tos::tos_api::tosNode_SignatureSet>(node_ordinary.release())),
      fixture, "node-ordinary-under-pq-set");

  auto node_simplex = tos::create_tl_object<tos::tos_api::tosNode_signatureSet_simplex>();
  node_simplex->cc_seqno_ = Fixture::catchain_seqno;
  node_simplex->validator_set_hash_ = fixture.validator_set->get_validator_set_hash();
  node_simplex->session_id_ = fixture.session;
  node_simplex->slot_ = Fixture::slot;
  node_simplex->candidate_ = candidate(fixture.id);
  node_simplex->final_ = true;
  expect_legacy_refusal(
      block::BlockSignatureSet::fetch(tos::tl_object_ptr<tos::tos_api::tosNode_SignatureSet>(node_simplex.release())),
      fixture, "node-simplex-under-pq-set");

  auto lite_ordinary = tos::create_tl_object<tos::lite_api::liteServer_signatureSet_ordinary>();
  lite_ordinary->catchain_seqno_ = Fixture::catchain_seqno;
  lite_ordinary->validator_set_hash_ = fixture.validator_set->get_validator_set_hash();
  auto lite_ordinary_set =
      require_ok(block::BlockSignatureSet::fetch(
                     tos::tl_object_ptr<tos::lite_api::liteServer_SignatureSet>(lite_ordinary.release())),
                 "lite-ordinary-construction");
  expect_legacy_refusal(std::move(lite_ordinary_set), fixture, "lite-ordinary-under-pq-set");

  auto lite_simplex = tos::create_tl_object<tos::lite_api::liteServer_signatureSet_simplex>();
  lite_simplex->cc_seqno_ = Fixture::catchain_seqno;
  lite_simplex->validator_set_hash_ = fixture.validator_set->get_validator_set_hash();
  lite_simplex->session_id_ = fixture.session;
  lite_simplex->slot_ = Fixture::slot;
  lite_simplex->candidate_ = tos::serialize_tl_object(candidate(fixture.id), true);
  auto lite_simplex_set =
      require_ok(block::BlockSignatureSet::fetch(
                     tos::tl_object_ptr<tos::lite_api::liteServer_SignatureSet>(lite_simplex.release())),
                 "lite-simplex-construction");
  expect_legacy_refusal(std::move(lite_simplex_set), fixture, "lite-simplex-under-pq-set");

  std::printf("PQ_BLOCK_SIGNATURE_NO_LEGACY_OK cases=6\n");
  return 0;
}
