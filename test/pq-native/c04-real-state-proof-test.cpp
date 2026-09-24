// Offline C04 candidate: real PQ Config34 genesis -> seqno-1 Merkle/proof.
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "block/block-auto.h"
#include "block/block-db.h"
#include "block/block-parse.h"
#include "block/mc-config.h"
#include "common/delay.h"
#include "quic/quic-sender.h"
#include "validator/downloaders/wait-block-data.hpp"
#include "validator/fabric.h"
#include "validator/impl/applied-ext-message-cleanup.hpp"
#include "validator/impl/check-proof.hpp"
#include "validator/impl/ext-message-pool.hpp"
#include "validator/impl/shard.hpp"
#include "validator/manager.hpp"
#include "validator/pq-finality-verification.h"
#include "td/actor/actor.h"
#include "td/utils/port/path.h"
#include "vm/boc.h"
#include "vm/cells/MerkleUpdate.h"
#include "pq-block-signature-test-common.h"

using namespace tos;
using namespace tos::validator;
using pq_block_signature_test::require_ok;

namespace tos::validator {

// Suppress only network-heavy Manager startup. The real DB actor and the
// production broadcast/proof/apply methods remain in the path.
class PendingFinalityManagerActorProbe final : public ValidatorManagerImpl {
 public:
  PendingFinalityManagerActorProbe(BlockIdExt zero_id, std::string root)
      : ValidatorManagerImpl(ValidatorManagerOptions::create(zero_id, zero_id), std::move(root), {}, {}, {}, {}, {}) {
  }

  void start_up() override {
    db_ = create_db_actor(actor_id(this), db_root_, opts_);
    callback_ = std::make_unique<ValidatorManagerInterface::Callback>();
    ext_message_pool_ = td::actor::create_actor<ExtMessagePool>("c04-ext-messages", opts_, actor_id(this));
  }

  void seed_zerostate(BlockIdExt zero_id, td::Ref<MasterchainStateQ> state, td::BufferSlice boc,
                      td::Promise<td::Unit> promise) {
    auto after_file = [self = actor_id(this), zero_id, state, promise = std::move(promise)](
                          td::Result<td::Unit> result) mutable {
      if (result.is_error()) {
        promise.set_error(result.move_as_error());
        return;
      }
      td::actor::send_closure(self, &PendingFinalityManagerActorProbe::seed_zero_state_root, zero_id, state,
                              std::move(promise));
    };
    td::actor::send_closure(db_, &Db::store_zero_state_file, zero_id, std::move(boc),
                            td::PromiseCreator::lambda(std::move(after_file)));
  }

  void seed_zero_state_root(BlockIdExt zero_id, td::Ref<MasterchainStateQ> state, td::Promise<td::Unit> promise) {
    auto handle = create_empty_block_handle(zero_id);
    handle->set_logical_time(state->get_logical_time());
    handle->set_unix_time(state->get_unix_time());
    handle->set_split(false);
    handle->set_merge(false);
    handle->set_is_key_block(true);
    handle->set_applied();
    handle->set_applied_stored();
    handle->set_processed();
    last_masterchain_state_ = state;
    last_masterchain_block_id_ = zero_id;
    last_masterchain_block_handle_ = handle;
    last_key_block_handle_ = handle;
    last_known_key_block_handle_ = handle;
    auto on_state = [self = actor_id(this), handle, promise = std::move(promise)](
                        td::Result<td::Ref<ShardState>> result) mutable {
      if (result.is_error()) {
        promise.set_error(result.move_as_error());
        return;
      }
      td::actor::send_closure(self, &PendingFinalityManagerActorProbe::store_zero_handle, handle, std::move(promise));
    };
    td::actor::send_closure(db_, &Db::store_block_state, handle, td::Ref<ShardState>{state}, vm::StoreCellHint{},
                            td::PromiseCreator::lambda(std::move(on_state)));
  }

  void store_zero_handle(BlockHandle handle, td::Promise<td::Unit> promise) {
    td::actor::send_closure(db_, &Db::store_block_handle, std::move(handle), std::move(promise));
  }

  void broadcast_bad_then_good(BlockIdExt id, td::BufferSlice data, td::Ref<block::BlockSignatureSet> bad,
                               td::Ref<block::BlockSignatureSet> good, td::Promise<td::Unit> promise) {
    cached_masterchain_block_candidates_.put(id, std::move(data));
    const auto expiry = td::Time::now() + 10.0;
    auto first = pending_block_finality_.admit(
        id, PendingBlockFinalitySender::remote(PublicKeyHash{pq_block_signature_test::hash_of("C04-bad")}),
        PendingBlockFinalityCandidate{std::move(bad), BroadcastSource::consensus_overlay}, 4096,
        PendingFinalityCapacity::Shared, false, true, expiry);
    auto second = pending_block_finality_.admit(
        id, PendingBlockFinalitySender::remote(PublicKeyHash{pq_block_signature_test::hash_of("C04-good")}),
        PendingBlockFinalityCandidate{std::move(good), BroadcastSource::consensus_overlay}, 4096,
        PendingFinalityCapacity::Shared, false, true, expiry);
    if (!first.admitted() || !second.admitted() || !pending_block_finality_.get_if_exists(id) ||
        pending_block_finality_.get_if_exists(id)->size() != 2) {
      return promise.set_error(td::Status::Error("C04 bad-front/good-back queue was not admitted"));
    }
    std::cout << "C04_MANAGER_QUEUE_ADMITTED entries=2\n";
    try_process_pending_block_finality(id);
    await_queue_drained(id, td::Timestamp::in(5.0), std::move(promise));
  }

  void await_queue_drained(BlockIdExt id, td::Timestamp deadline, td::Promise<td::Unit> promise) {
    if (!pending_block_finality_.get_if_exists(id) && !cached_masterchain_block_candidates_.contains(id) &&
        last_masterchain_block_handle_ && last_masterchain_block_handle_->id() == id &&
        last_masterchain_block_handle_->processed()) {
      return promise.set_value(td::Unit());
    }
    if (deadline.is_in_past()) {
      auto *pending = pending_block_finality_.get_if_exists(id);
      std::cerr << "C04_MANAGER_QUEUE_TIMEOUT candidate_present="
                << cached_masterchain_block_candidates_.contains(id) << " pending_entries="
                << (pending ? pending->size() : 0) << " target_processed="
                << (last_masterchain_block_handle_ && last_masterchain_block_handle_->id() == id &&
                    last_masterchain_block_handle_->processed()) << '\n';
      return promise.set_error(td::Status::Error("C04 bad-front/good-back queue did not drain through apply"));
    }
    delay_action([self = actor_id(this), id, deadline, promise = std::move(promise)]() mutable {
      td::actor::send_closure(self, &PendingFinalityManagerActorProbe::await_queue_drained, id, deadline,
                              std::move(promise));
    }, td::Timestamp::in(0.01));
  }

  void verify_persisted(BlockIdExt zero_id, BlockIdExt target_id, RootHash expected_root,
                        td::BufferSlice expected_proof, td::Promise<td::Unit> promise) {
    if (!last_masterchain_block_handle_ || last_masterchain_block_handle_->id() != target_id ||
        !last_masterchain_block_handle_->processed()) {
      return promise.set_error(td::Status::Error("Manager did not process target masterchain block"));
    }
    auto db = db_.get();
    td::actor::send_closure(db, &Db::get_block_handle, target_id,
                            td::PromiseCreator::lambda(
                                [db, zero_id, target_id, expected_root, expected_proof = std::move(expected_proof),
                                 promise = std::move(promise)](td::Result<BlockHandle> result) mutable {
      if (result.is_error()) {
        return promise.set_error(result.move_as_error_prefix("DB target handle: "));
      }
      auto handle = result.move_as_ok();
      if (handle->id() != target_id || !handle->received() || !handle->inited_proof() ||
          !handle->received_state() || !handle->is_applied() || !handle->applied_stored() ||
          handle->state() != expected_root) {
        std::cerr << "C04_MANAGER_DB_FLAGS id=" << (handle->id() == target_id) << " received=" << handle->received()
                  << " proof=" << handle->inited_proof() << " state=" << handle->received_state()
                  << " applied=" << handle->is_applied() << " applied_stored=" << handle->applied_stored()
                  << " processed=" << handle->processed() << " root=" << handle->state().to_hex() << '\n';
        return promise.set_error(td::Status::Error("DB target handle lacks received/proof/state/applied flags or root"));
      }
      td::actor::send_closure(db, &Db::get_block_data, ConstBlockHandle{handle},
                              td::PromiseCreator::lambda(
                                  [db, zero_id, target_id, expected_root,
                                   expected_proof = std::move(expected_proof), handle = std::move(handle),
                                   promise = std::move(promise)](td::Result<td::Ref<BlockData>> result) mutable {
        if (result.is_error()) {
          return promise.set_error(result.move_as_error_prefix("DB target data: "));
        }
        if (result.ok()->block_id() != target_id || result.ok()->file_hash() != target_id.file_hash) {
          return promise.set_error(td::Status::Error("DB target data changed"));
        }
        td::actor::send_closure(db, &Db::get_block_proof, ConstBlockHandle{handle},
                                td::PromiseCreator::lambda(
                                    [db, zero_id, expected_root, expected_proof = std::move(expected_proof),
                                     handle = std::move(handle), promise = std::move(promise)](
                                        td::Result<td::Ref<Proof>> result) mutable {
          if (result.is_error()) {
            return promise.set_error(result.move_as_error_prefix("DB target proof: "));
          }
          if (result.ok()->data().as_slice() != expected_proof.as_slice()) {
            return promise.set_error(td::Status::Error("DB target proof bytes changed"));
          }
          td::actor::send_closure(db, &Db::get_block_state, ConstBlockHandle{handle},
                                  td::PromiseCreator::lambda(
                                      [db, zero_id, target_id = handle->id(), expected_root, promise = std::move(promise)](
                                          td::Result<td::Ref<ShardState>> result) mutable {
            if (result.is_error()) {
              return promise.set_error(result.move_as_error_prefix("DB target state: "));
            }
            if (result.ok()->root_hash() != expected_root) {
              return promise.set_error(td::Status::Error("DB target state root changed"));
            }
            td::actor::send_closure(db, &Db::get_block_handle, zero_id,
                                    td::PromiseCreator::lambda(
                                        [target_id, promise = std::move(promise)](td::Result<BlockHandle> result) mutable {
              if (result.is_error()) {
                return promise.set_error(result.move_as_error_prefix("DB predecessor handle: "));
              }
              if (!result.ok()->inited_next() || result.ok()->one_next(true) != target_id) {
                return promise.set_error(td::Status::Error("DB predecessor next does not identify target"));
              }
              promise.set_value(td::Unit());
            }));
          }));
        }));
      }));
    }));
  }
};

}  // namespace tos::validator

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
  auto db_root = require_ok(td::mkdtemp("", "c04-manager-"), "C04 manager DB directory");
  std::cout << "C04_MANAGER_DB_ROOT=" << db_root << '\n';
  std::filesystem::create_directories(db_root + "/static");
  {
    std::ofstream static_zero(db_root + "/static/" + id0.file_hash.to_hex(), std::ios::binary);
    static_zero.write(boc.as_slice().data(), static_cast<std::streamsize>(boc.size()));
    if (!static_zero) {
      std::cerr << "C04_MANAGER_ACTOR_FAILED: cannot provision genesis in StaticFilesDb\n";
      return 1;
    }
  }
  {
    td::actor::Scheduler scheduler({1});
    td::actor::ActorOwn<PendingFinalityManagerActorProbe> manager;
    std::optional<td::Result<td::Unit>> result;
    scheduler.run_in_context([&] {
      manager = td::actor::create_actor<PendingFinalityManagerActorProbe>("c04-real-manager", id0, db_root);
      td::actor::send_closure(manager, &PendingFinalityManagerActorProbe::seed_zerostate, id0, state0, boc.clone(),
                              td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
                                result.emplace(std::move(outcome));
                              }));
    });
    auto wait_result = [&]() {
      auto deadline = td::Timestamp::in(30.0);
      while (!result.has_value() && !deadline.is_in_past()) {
        scheduler.run(0.01);
      }
      if (!result.has_value()) {
        std::cerr << "C04_MANAGER_ACTOR_FAILED: actor step timed out\n";
        return false;
      }
      if (result->is_error()) {
        std::cerr << "C04_MANAGER_ACTOR_FAILED: " << result->error().to_string() << '\n';
        return false;
      }
      return true;
    };
    if (!wait_result()) {
      return 1;
    }
    std::cout << "C04_MANAGER_ZERO_STATE_STORED\n";
    result.reset();
    scheduler.run_in_context([&] {
      td::actor::send_closure(manager, &PendingFinalityManagerActorProbe::broadcast_bad_then_good, id1,
                              block_boc.clone(), bad, good,
                              td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
                                result.emplace(std::move(outcome));
                              }));
    });
    if (!wait_result()) {
      return 1;
    }
    std::cout << "C04_MANAGER_BAD_FRONT_GOOD_APPLIED_OK\n";
    result.reset();
    scheduler.run_in_context([&] {
      td::actor::send_closure(manager, &PendingFinalityManagerActorProbe::verify_persisted, id0, id1,
                              expected_state_root, proof.ok().clone(),
                              td::PromiseCreator::lambda([&](td::Result<td::Unit> outcome) {
                                result.emplace(std::move(outcome));
                              }));
    });
    if (!wait_result()) {
      return 1;
    }
    std::cout << "C04_MANAGER_DB_APPLIED_OK block=" << id1.to_str() << " root=" << expected_state_root.to_hex()
              << '\n';
    scheduler.run_in_context([&] { manager.reset(); });
    scheduler.stop();
  }
  std::cout << "C04_REAL_PROOF_OK session=" << context.expected_session_id.to_hex()
            << " block=" << id1.to_str() << " proof_bytes=" << proof.ok().size() << '\n';
  return 0;
}
