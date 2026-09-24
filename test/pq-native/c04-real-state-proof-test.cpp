// Offline C04 candidate: real PQ Config34 genesis -> seqno-1 Merkle/proof.
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "block/block-auto.h"
#include "block/block-db.h"
#include "block/block-parse.h"
#include "block/mc-config.h"
#include "validator/downloaders/wait-block-data.hpp"
#include "validator/fabric.h"
#include "validator/impl/check-proof.hpp"
#include "validator/impl/shard.hpp"
#include "validator/pq-finality-verification.h"
#include "vm/boc.h"
#include "vm/cells/MerkleUpdate.h"
#include "pq-block-signature-test-common.h"

using namespace tos;
using namespace tos::validator;
using pq_block_signature_test::require_ok;

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "usage: c04-real-state-proof-test GENESIS_BOC\n";
    return 2;
  }
  std::ifstream input(argv[1], std::ios::binary);
  std::ostringstream bytes;
  bytes << input.rdbuf();
  if (!input) {
    std::cerr << "C04_REAL_STATE_FAILED: genesis read\n";
    return 1;
  }
  td::BufferSlice boc{bytes.str()};
  auto root0 = require_ok(vm::std_boc_deserialize(boc.as_slice()), "genesis BOC");
  auto id0 = BlockIdExt{masterchainId, shardIdAll, 0, td::Bits256(root0->get_hash().bits()),
                        block::compute_file_hash(boc)};
  auto state0 = require_ok(MasterchainStateQ::fetch(id0, boc.clone(), root0), "genesis state fetch");
  block::gen::ShardStateUnsplit::Record record;
  if (!block::gen::t_ShardStateUnsplit.cell_unpack(root0, record) || record.seq_no != 0) {
    std::cerr << "C04_REAL_STATE_FAILED: genesis header\n";
    return 1;
  }
  pq_block_signature_test::Fixture keys;
  auto target_time = record.gen_utime + 1;
  constexpr CatchainSeqno cc = 0;
  auto vset = state0->get_validator_set(ShardIdFull{masterchainId}, target_time, cc);
  if (vset.is_null() || vset->export_vector().size() != 4) {
    std::cerr << "C04_REAL_STATE_FAILED: Config34 validator set\n";
    return 1;
  }
  auto nodes = vset->export_vector();
  for (size_t i = 0; i < keys.validator_ids.size(); ++i) {
    auto node = vset->get_validator(keys.validator_ids[i]);
    if (!node || !node->is_pq() || node->pq_public_key != keys.stores[i].consensus_key().public_key ||
        node->weight != 17) {
      std::cerr << "C04_REAL_STATE_FAILED: Config34 signer mismatch index=" << i << "\n";
      return 1;
    }
  }
  // A post-genesis masterchain state must record the zerostate in OldMcBlocks.
  auto custom_root = record.custom->prefetch_ref();
  block::gen::McStateExtra::Record mc_state_extra;
  if (custom_root.is_null() || !block::gen::t_McStateExtra.cell_unpack(custom_root, mc_state_extra)) {
    std::cerr << "C04_REAL_STATE_FAILED: genesis McStateExtra unpack\n";
    return 1;
  }
  vm::AugmentedDictionary old_blocks(mc_state_extra.r1.prev_blocks, 32, block::tlb::aug_OldMcBlocksInfo);
  vm::CellBuilder zero_ref;
  zero_ref.store_bool_bool(true);
  zero_ref.store_long(0, 64).store_long(0, 32).store_bits(id0.root_hash.cbits(), 256)
      .store_bits(id0.file_hash.cbits(), 256);
  if (!old_blocks.set_builder(td::BitArray<32>::zero(), zero_ref)) {
    std::cerr << "C04_REAL_STATE_FAILED: OldMcBlocks insert\n";
    return 1;
  }
  mc_state_extra.r1.prev_blocks = old_blocks.get_root();
  td::Ref<vm::Cell> new_custom_root;
  if (!block::gen::t_McStateExtra.cell_pack(new_custom_root, mc_state_extra)) {
    std::cerr << "C04_REAL_STATE_FAILED: McStateExtra repack\n";
    return 1;
  }
  vm::CellBuilder custom_ref;
  custom_ref.store_bool_bool(true);
  custom_ref.store_ref_bool(new_custom_root);
  record.custom = custom_ref.as_cellslice_ref();
  record.seq_no = 1;
  record.gen_utime = target_time;
  record.gen_lt += 1000;
  td::Ref<vm::Cell> root1;
  if (!block::gen::t_ShardStateUnsplit.cell_pack(root1, record)) {
    std::cerr << "C04_REAL_STATE_FAILED: state1 pack\n";
    return 1;
  }
  auto update = vm::CellBuilder::create_merkle_update(root0, root1);
  auto applied = require_ok(vm::MerkleUpdate::apply(root0, update, nullptr), "seq0-to-seq1 Merkle apply");
  if (applied->get_hash() != root1->get_hash()) {
    std::cerr << "C04_REAL_STATE_FAILED: Merkle new root mismatch\n";
    return 1;
  }
  auto wrong_old_root = vm::CellBuilder{}.store_long(123, 32).finalize_novm();
  if (vm::MerkleUpdate::apply(wrong_old_root, update, nullptr).is_ok()) {
    std::cerr << "C04_REAL_STATE_FAILED: wrong Merkle predecessor was accepted\n";
    return 1;
  }
  auto state1_boc = require_ok(vm::std_boc_serialize(root1, 31), "state1 BOC");
  auto id1_state = BlockIdExt{masterchainId, shardIdAll, 1, td::Bits256(root1->get_hash().bits()),
                              block::compute_file_hash(state1_boc)};
  require_ok(MasterchainStateQ::fetch(id1_state, state1_boc.clone(), root1), "state1 fetch");
  std::cout << "C04_REAL_STATE_OK config34_hash=" << vset->get_validator_set_hash()
            << " old=" << root0->get_hash().bits().to_hex(256)
            << " new=" << root1->get_hash().bits().to_hex(256) << '\n';

  block::gen::BlockInfo::Record info{};
  info.version = 0;
  info.not_master = false;
  info.after_merge = info.before_split = info.after_split = false;
  info.want_split = info.want_merge = false;
  info.key_block = info.vert_seqno_incr = false;
  info.flags = 0;
  info.seq_no = 1;
  info.vert_seq_no = 0;
  vm::CellBuilder shard;
  block::ShardId{ShardIdFull{masterchainId}}.serialize(shard);
  info.shard = shard.as_cellslice_ref();
  info.gen_utime = target_time;
  info.start_lt = record.gen_lt - 1;
  info.end_lt = record.gen_lt;
  info.gen_validator_list_hash_short = vset->get_validator_set_hash();
  info.gen_catchain_seqno = cc;
  info.min_ref_mc_seqno = 0;
  info.prev_key_block_seqno = 0;
  vm::CellBuilder prev_ref;
  prev_ref.store_long(0, 64).store_long(0, 32).store_bits(id0.root_hash.cbits(), 256)
      .store_bits(id0.file_hash.cbits(), 256);
  info.prev_ref = prev_ref.finalize_novm();
  td::Ref<vm::Cell> info_cell;
  if (!block::gen::t_BlockInfo.cell_pack(info_cell, info)) {
    std::cerr << "C04_REAL_PROOF_FAILED: BlockInfo pack\n";
    return 1;
  }
  vm::CellBuilder empty_builder;
  empty_builder.store_bool_bool(false);
  auto empty = empty_builder.finalize_novm();
  vm::CellBuilder empty_fees_builder;
  empty_fees_builder.store_zeroes(11);
  auto empty_fees = empty_fees_builder.finalize_novm();
  block::gen::McBlockExtra::Record mc_extra{};
  mc_extra.key_block = false;
  mc_extra.shard_hashes = vm::load_cell_slice_ref(empty);
  mc_extra.shard_fees = vm::load_cell_slice_ref(empty_fees);
  mc_extra.r1.prev_blk_signatures = vm::load_cell_slice_ref(empty);
  mc_extra.r1.recover_create_msg = vm::load_cell_slice_ref(empty);
  mc_extra.r1.mint_msg = vm::load_cell_slice_ref(empty);
  td::Ref<vm::Cell> mc_extra_cell;
  if (!block::gen::t_McBlockExtra.cell_pack(mc_extra_cell, mc_extra)) {
    std::cerr << "C04_REAL_PROOF_FAILED: McBlockExtra pack\n";
    return 1;
  }
  block::gen::BlockExtra::Record extra{};
  extra.in_msg_descr = empty;
  extra.out_msg_descr = empty;
  extra.account_blocks = empty;
  vm::CellBuilder custom;
  custom.store_bool_bool(true);
  custom.store_ref_bool(mc_extra_cell);
  extra.custom = custom.as_cellslice_ref();
  td::Ref<vm::Cell> extra_cell;
  if (!block::gen::t_BlockExtra.cell_pack(extra_cell, extra)) {
    std::cerr << "C04_REAL_PROOF_FAILED: BlockExtra pack\n";
    return 1;
  }
  block::ValueFlow flow{block::ValueFlow::SetZero{}};
  vm::CellBuilder flow_builder;
  if (!flow.store(flow_builder)) {
    std::cerr << "C04_REAL_PROOF_FAILED: ValueFlow pack\n";
    return 1;
  }
  auto block_root = vm::CellBuilder{}.store_long(0x11ef55aa, 32).store_long(0, 32).store_ref(info_cell)
                        .store_ref(flow_builder.finalize()).store_ref(update).store_ref(extra_cell).finalize_novm();
  auto block_boc = require_ok(vm::std_boc_serialize(block_root, 31), "block BOC");
  auto id1 = BlockIdExt{masterchainId, shardIdAll, 1, td::Bits256(block_root->get_hash().bits()),
                        block::compute_file_hash(block_boc)};
  // A proof that parses is not necessarily an applicable block. Pin the
  // production state transition before using this fixture in a DB-backed
  // Manager test.
  auto parsed_block = require_ok(create_block(id1, block_boc.clone()), "C04 apply preflight block");
  auto replay_state = require_ok(MasterchainStateQ::fetch(id0, boc.clone(), root0), "C04 apply preflight state");
  auto application = replay_state.write().apply_block(id1, parsed_block, nullptr);
  if (application.is_error()) {
    std::cerr << "C04_REAL_APPLY_FAILED: " << application.to_string() << '\n';
    return 1;
  }
  const auto expected_state_root = RootHash{root1->get_hash().bits()};
  if (replay_state->root_hash() != expected_state_root) {
    std::cerr << "C04_REAL_APPLY_FAILED: expected root " << expected_state_root.to_hex() << ", actual "
              << replay_state->root_hash().to_hex() << '\n';
    return 1;
  }
  std::cout << "C04_REAL_APPLY_OK root=" << replay_state->root_hash().to_hex() << '\n';
  auto context = require_ok(derive_pq_finality_context(*state0, vset, id1, 0, 0), "PQ session");
  auto candidate = pq_block_signature_test::candidate(id1);
  auto pairs = keys.sign({0, 1, 2}, context.expected_session_id, pq_block_signature_test::Fixture::slot,
                         candidate, true, id1);
  const ValidatorWeight quorum_weight = 51;
  auto good_cell = require_ok(block::BlockSignatureSet::serialize_simplex_pq(
      pq_block_signature_test::clone_pairs(pairs), cc, vset->get_validator_set_hash(), quorum_weight,
      context.expected_session_id, pq_block_signature_test::Fixture::slot, candidate), "good certificate cell");
  ValidatorWeight parsed_weight = 0;
  auto good = require_ok(block::BlockSignatureSet::fetch(good_cell, parsed_weight), "good certificate");
  require_ok(block::verify_pq_finality(context, *good, block::FinalityRole::Final), "good PQ verify");
  auto wrong_session = context;
  wrong_session.expected_session_id = pq_block_signature_test::hash_of("wrong-C04-session");
  if (block::verify_pq_finality(wrong_session, *good, block::FinalityRole::Final).is_ok()) {
    std::cerr << "C04_REAL_PROOF_FAILED: wrong trusted session was accepted\n";
    return 1;
  }
  PendingBlockProofFailureSource source{};
  auto proof = WaitBlockData::generate_proof(id1, block_root, good, state0, source);
  if (proof.is_error()) {
    std::cerr << "C04_REAL_PROOF_FAILED: " << proof.error().to_string() << '\n';
    return 1;
  }
  auto parsed_proof = require_ok(create_proof(id1, proof.ok().clone()), "parse generated BlockProof");
  auto header = require_ok(parsed_proof->get_basic_header_info(), "BlockProof header");
  auto envelope = require_ok(parse_block_proof_signature_envelope(
      require_ok(parsed_proof->get_root_cell(), "BlockProof root")), "BlockProof signatures");
  if (header.cc_seqno != cc || header.validator_set_hash != vset->get_validator_set_hash() ||
      header.prev_key_mc_seqno != 0 || envelope.block_id != id1 || envelope.signatures.is_null() ||
      envelope.signatures->get_validator_set_hash() != vset->get_validator_set_hash()) {
    std::cerr << "C04_REAL_PROOF_FAILED: generated BlockProof coordinates differ\n";
    return 1;
  }
  auto bad_cell = require_ok(block::BlockSignatureSet::serialize_simplex_pq(
      pq_block_signature_test::clone_pairs(pairs), cc, vset->get_validator_set_hash() ^ 1u, quorum_weight,
      context.expected_session_id, pq_block_signature_test::Fixture::slot, candidate), "bad certificate cell");
  auto bad = require_ok(block::BlockSignatureSet::fetch(bad_cell, parsed_weight), "bad certificate");
  auto bad_proof = WaitBlockData::generate_proof(id1, block_root, bad, state0, source);
  if (bad_proof.is_ok() || source != PendingBlockProofFailureSource::FinalityEvidence) {
    std::cerr << "C04_REAL_PROOF_FAILED: wrong hash certificate was not attributed to finality evidence\n";
    return 1;
  }
  std::cout << "C04_REAL_PROOF_OK session=" << context.expected_session_id.to_hex()
            << " block=" << id1.to_str() << " proof_bytes=" << proof.ok().size() << '\n';
  return 0;
}
