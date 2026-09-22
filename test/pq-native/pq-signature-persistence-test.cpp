/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <algorithm>
#include <array>
#include <limits>
#include <mutex>
#include <optional>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "crypto/pq/pq-bytes.h"
#include "td/actor/actor.h"
#include "td/utils/Random.h"
#include "td/utils/filesystem.h"
#include "test/pq-native/pq-block-signature-test-common.h"
#include "validator/db/rootdb.hpp"
#include "validator/fabric.h"
#include "validator/impl/accept-block.hpp"
#include "validator/impl/check-proof.hpp"
#include "validator/impl/top-shard-descr.hpp"
#include "validator/interfaces/db.h"
#include "validator/pq-finality-verification.h"
#include "validator/validator.h"
#include "vm/cells/CellString.h"
#include "vm/cells/MerkleProof.h"

namespace {

using namespace pq_block_signature_test;
using namespace tos;
using namespace tos::validator;

td::Ref<ValidatorManagerOptions> make_options() {
  auto opts = ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{}, false, 0.0, 0.0, 0.0, 0.0, 0.0, 0, true);
  auto& writable = opts.write();
  writable.set_disable_rocksdb_stats(true);
  writable.set_celldb_compress_depth(0);
  writable.set_celldb_in_memory(false);
  writable.set_celldb_v2(false);
  writable.set_celldb_disable_bloom_filter(true);
  writable.set_permanent_celldb(false);
  writable.set_catchain_broadcast_speed_multiplier(1.0);
  return opts;
}

class RootDbRoundTrip {
 public:
  explicit RootDbRoundTrip(std::string root) : root_(std::move(root)), scheduler_({1}) {
    td::rmrf(root_).ignore();
    td::mkpath(root_ + "/").ensure();
    scheduler_.run_in_context([&] {
      db_ = td::actor::create_actor<RootDb>("pq-signature-rootdb", td::actor::ActorId<ValidatorManager>{}, root_,
                                            make_options());
    });
  }

  ~RootDbRoundTrip() {
    scheduler_.run_in_context([&] {
      db_.reset();
      td::actor::SchedulerContext::get().stop();
    });
    while (scheduler_.run(1)) {
    }
    td::rmrf(root_).ignore();
  }

  void store(BlockHandle handle, td::Ref<block::BlockSignatureSet> signatures,
             td::Ref<block::ValidatorSet> validator_set) {
    ask<td::Unit>([&](td::Promise<td::Unit> promise) {
      td::actor::send_closure(db_.get(), &Db::store_block_signatures, handle, std::move(signatures),
                              std::move(validator_set), std::move(promise));
    });
  }

  td::Ref<block::BlockSignatureSet> load(ConstBlockHandle handle) {
    return ask<td::Ref<block::BlockSignatureSet>>([&](auto promise) {
      td::actor::send_closure(db_.get(), &Db::get_block_signatures, handle, std::move(promise));
    });
  }

  void store_proof(BlockHandle handle, td::Ref<Proof> proof) {
    ask<td::Unit>([&](td::Promise<td::Unit> promise) {
      td::actor::send_closure(db_.get(), &Db::store_block_proof, handle, std::move(proof), std::move(promise));
    });
  }

  td::Ref<Proof> load_proof(ConstBlockHandle handle) {
    return ask<td::Ref<Proof>>(
        [&](auto promise) { td::actor::send_closure(db_.get(), &Db::get_block_proof, handle, std::move(promise)); });
  }

 private:
  template <class T, class Send>
  T ask(Send send) {
    std::mutex mutex;
    std::optional<td::Result<T>> result;
    scheduler_.run_in_context([&] {
      send(td::PromiseCreator::lambda([&](td::Result<T> value) {
        std::lock_guard guard(mutex);
        result.emplace(std::move(value));
      }));
    });
    const auto deadline = td::Timestamp::in(60.0);
    while (true) {
      {
        std::lock_guard guard(mutex);
        if (result.has_value()) {
          if (result->is_error()) {
            fail("PQ_SIGNATURE_PERSISTENCE_DB_ERROR: " + result->error().message().str());
          }
          return result->move_as_ok();
        }
      }
      if (deadline.is_in_past()) {
        fail("PQ_SIGNATURE_PERSISTENCE_DB_TIMEOUT");
      }
      if (!scheduler_.run(0.05)) {
        fail("PQ_SIGNATURE_PERSISTENCE_SCHEDULER_STOPPED");
      }
    }
  }

  std::string root_;
  td::actor::Scheduler scheduler_;
  td::actor::ActorOwn<Db> db_;
};

class FocusedConfigHolder final : public ConfigHolder {
 public:
  FocusedConfigHolder(td::int32 header_global_id, td::int32 config_global_id,
                      td::Ref<block::ValidatorSet> validator_set, ValidatorSessionConfig session_config,
                      SelectedNewConsensusConfig selected_config)
      : header_global_id_(header_global_id)
      , config_global_id_(config_global_id)
      , validator_set_(std::move(validator_set))
      , session_config_(session_config)
      , selected_config_(std::move(selected_config)) {
  }

  td::Ref<block::ValidatorSet> get_total_validator_set(int) const override {
    return validator_set_;
  }
  td::Ref<block::ValidatorSet> get_validator_set(ShardIdFull, UnixTime, CatchainSeqno) const override {
    return validator_set_;
  }
  std::pair<UnixTime, UnixTime> get_validator_set_start_stop(int) const override {
    return {0, std::numeric_limits<UnixTime>::max()};
  }
  td::int32 get_global_id() const override {
    return header_global_id_;
  }
  td::Result<td::int32> get_config_global_id() const override {
    return config_global_id_;
  }
  ValidatorSessionConfig get_consensus_config() const override {
    return session_config_;
  }
  td::optional<SelectedNewConsensusConfig> get_selected_new_consensus_config(WorkchainId) const override {
    return selected_config_;
  }

 private:
  td::int32 header_global_id_;
  td::int32 config_global_id_;
  td::Ref<block::ValidatorSet> validator_set_;
  ValidatorSessionConfig session_config_;
  SelectedNewConsensusConfig selected_config_;
};

class FocusedMasterchainState final : public MasterchainState {
 public:
  FocusedMasterchainState(BlockIdExt id, td::int32 global_id, BlockSeqno vertical_seqno, BlockIdExt last_key_block_id,
                          td::Ref<block::ValidatorSet> validator_set, td::Ref<block::McShardHashI> shard_top,
                          ValidatorSessionConfig session_config, SelectedNewConsensusConfig selected_config,
                          std::vector<BlockIdExt> ancestors, td::optional<td::int32> config_global_id = {})
      : id_(std::move(id))
      , global_id_(global_id)
      , vertical_seqno_(vertical_seqno)
      , last_key_block_id_(std::move(last_key_block_id))
      , validator_set_(std::move(validator_set))
      , shard_top_(std::move(shard_top))
      , session_config_(session_config)
      , selected_config_(std::move(selected_config))
      , ancestors_(std::move(ancestors))
      , config_global_id_(config_global_id ? config_global_id.value() : global_id_) {
  }

  bool disable_boc() const override {
    return false;
  }
  UnixTime get_unix_time() const override {
    return 0;
  }
  LogicalTime get_logical_time() const override {
    return 0;
  }
  td::int32 get_global_id() const override {
    return global_id_;
  }
  ShardIdFull get_shard() const override {
    return id_.shard_full();
  }
  BlockSeqno get_seqno() const override {
    return id_.seqno();
  }
  BlockIdExt get_block_id() const override {
    return id_;
  }
  RootHash root_hash() const override {
    return id_.root_hash;
  }
  td::Ref<vm::Cell> root_cell() const override {
    return {};
  }
  td::optional<BlockIdExt> get_master_ref() const override {
    return {};
  }
  td::Status validate_deep() const override {
    return td::Status::OK();
  }
  bool before_split() const override {
    return false;
  }
  td::Result<td::Ref<MessageQueue>> message_queue() const override {
    return td::Status::Error("focused masterchain state has no message queue");
  }
  td::Status apply_block(BlockIdExt, td::Ref<BlockData>, vm::StoreCellHint*) override {
    return td::Status::Error("focused masterchain state is immutable");
  }
  td::Result<td::Ref<ShardState>> merge_with(const ShardState&) const override {
    return td::Status::Error("focused masterchain state cannot merge");
  }
  td::Result<std::pair<td::Ref<ShardState>, td::Ref<ShardState>>> split() const override {
    return td::Status::Error("focused masterchain state cannot split");
  }
  td::Result<td::BufferSlice> serialize() const override {
    return td::Status::Error("focused masterchain state is not serializable");
  }
  td::Status serialize_to_file(td::FileFd&) const override {
    return td::Status::Error("focused masterchain state is not serializable");
  }

  td::Ref<block::ValidatorSet> get_validator_set(ShardIdFull) const override {
    return validator_set_;
  }
  td::Ref<block::ValidatorSet> get_next_validator_set(ShardIdFull) const override {
    return {};
  }
  td::Ref<block::ValidatorSet> get_total_validator_set(int) const override {
    return validator_set_;
  }
  bool rotated_all_shards() const override {
    return false;
  }
  std::vector<td::Ref<McShardHash>> get_shards() const override {
    return {};
  }
  td::Ref<McShardHash> get_shard_from_config(ShardIdFull, bool) const override {
    return shard_top_;
  }
  CatchainSeqno get_shard_cc_seqno(ShardIdFull) const override {
    return validator_set_->get_catchain_seqno();
  }
  bool workchain_is_active(WorkchainId) const override {
    return true;
  }
  td::uint32 persistent_state_split_depth(WorkchainId) const override {
    return 0;
  }
  td::uint32 monitor_min_split_depth(WorkchainId) const override {
    return 0;
  }
  td::uint32 min_split_depth(WorkchainId) const override {
    return 0;
  }
  BlockSeqno min_ref_masterchain_seqno() const override {
    return 0;
  }
  bool ancestor_is_valid(BlockIdExt id) const override {
    return check_old_mc_block_id(id, false);
  }
  ValidatorSessionConfig get_consensus_config() const override {
    return session_config_;
  }
  td::optional<SelectedNewConsensusConfig> get_selected_new_consensus_config(WorkchainId) const override {
    return selected_config_;
  }
  td::optional<NewConsensusConfig> get_new_consensus_config(WorkchainId) const override {
    return selected_config_.config;
  }
  BlockSeqno get_vertical_seqno() const override {
    return vertical_seqno_;
  }
  BlockIdExt last_key_block_id() const override {
    return last_key_block_id_;
  }
  BlockIdExt next_key_block_id(BlockSeqno) const override {
    return {};
  }
  BlockIdExt prev_key_block_id(BlockSeqno) const override {
    return last_key_block_id_;
  }
  bool is_key_state() const override {
    return false;
  }
  bool get_old_mc_block_id(BlockSeqno seqno, BlockIdExt& block_id, LogicalTime*) const override {
    for (const auto& candidate : ancestors_) {
      if (candidate.seqno() == seqno) {
        block_id = candidate;
        return true;
      }
    }
    return false;
  }
  bool check_old_mc_block_id(const BlockIdExt& block_id, bool) const override {
    return std::find(ancestors_.begin(), ancestors_.end(), block_id) != ancestors_.end();
  }
  td::Result<td::Ref<ConfigHolder>> get_config_holder() const override {
    return td::Ref<FocusedConfigHolder>{true,           global_id_,      config_global_id_,
                                        validator_set_, session_config_, selected_config_};
  }
  block::WorkchainSet get_workchain_list() const override {
    return {};
  }
  block::SizeLimitsConfig::ExtMsgLimits get_ext_msg_limits() const override {
    return {};
  }
  block::ImportedMsgQueueLimits get_imported_msg_queue_limits(bool) const override {
    return {};
  }

 private:
  BlockIdExt id_;
  td::int32 global_id_;
  BlockSeqno vertical_seqno_;
  BlockIdExt last_key_block_id_;
  td::Ref<block::ValidatorSet> validator_set_;
  td::Ref<block::McShardHashI> shard_top_;
  ValidatorSessionConfig session_config_;
  SelectedNewConsensusConfig selected_config_;
  std::vector<BlockIdExt> ancestors_;
  td::int32 config_global_id_;
};

struct LargeFixture {
  std::vector<pq::ValidatorPQKeyStore> stores;
  std::vector<ValidatorId> validator_ids;
  td::Ref<block::ValidatorSet> validator_set;
  BlockIdExt id;
  ValidatorSessionId session;
  td::uint32 slot;

  LargeFixture(std::size_t count, td::uint32 discriminator)
      : id(block_id("pq-persistence-" + std::to_string(count)))
      , session(hash_of("pq-persistence-session-" + std::to_string(count)))
      , slot(3000 + discriminator) {
    std::vector<ValidatorDescr> descriptors;
    descriptors.reserve(count);
    stores.reserve(count);
    validator_ids.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
      std::array<char, 32> seed{};
      for (std::size_t j = 0; j < seed.size(); ++j) {
        seed[j] = static_cast<char>((i * 131 + j * 17 + discriminator) & 0xff);
      }
      auto store = pq::ValidatorPQKeyStore::from_seed(std::string_view(seed.data(), seed.size()));
      if (!store.has_value()) {
        fail("PQ_SIGNATURE_PERSISTENCE_KEY_DERIVATION_FAILED");
      }
      auto validator_id =
          ValidatorId{hash_of("pq-persistence-validator-" + std::to_string(discriminator) + "-" + std::to_string(i))};
      const auto& key = store->consensus_key();
      descriptors.emplace_back(validator_id, static_cast<td::uint16>(key.algorithm_id), key_id_of(key), key.public_key,
                               1, hash_of("pq-persistence-adnl-" + std::to_string(i)));
      validator_ids.push_back(validator_id);
      stores.push_back(std::move(*store));
    }
    validator_set =
        td::Ref<block::ValidatorSet>{true, 7000 + discriminator, ShardIdFull{masterchainId}, std::move(descriptors)};
  }

  td::Ref<block::BlockSignatureSet> signatures() {
    auto candidate_data = candidate(id, "pq-persistence-parent");
    auto message = require_ok(
        block::BlockSignatureSet::build_simplex_data_to_sign(session, slot, candidate_data, true, id), "preimage");
    std::vector<block::PQBlockSignature> pairs;
    pairs.reserve(stores.size());
    for (std::size_t i = 0; i < stores.size(); ++i) {
      auto signed_vote = stores[i].sign_consensus(view(message.as_slice()));
      if (!signed_vote.has_value()) {
        fail("PQ_SIGNATURE_PERSISTENCE_SIGN_FAILED");
      }
      pairs.push_back({validator_ids[i], signed_vote->algorithm_id, td::BufferSlice(signed_vote->signature)});
    }
    return require_ok(block::BlockSignatureSet::create_simplex_pq_final(
                          std::move(pairs), validator_set->get_catchain_seqno(),
                          validator_set->get_validator_set_hash(), session, slot, std::move(candidate_data)),
                      "carrier");
  }
};

struct RawPair {
  ValidatorId validator_id;
  td::uint16 algorithm_id;
  td::Ref<vm::Cell> signature;
};

td::Ref<vm::Cell> candidate_cell(const tos::tl_object_ptr<tos_api::consensus_CandidateHashData>& candidate_data) {
  auto bytes = serialize_tl_object(candidate_data, true);
  return require_ok(vm::CellString::create(bytes.as_slice()), "candidate-cell");
}

td::Ref<vm::Cell> raw_signature_set(const std::vector<RawPair>& pairs, td::uint32 validator_hash,
                                    CatchainSeqno catchain_seqno, ValidatorWeight weight, ValidatorSessionId session,
                                    td::uint32 slot, td::Ref<vm::Cell> candidate_data, unsigned tag = 0x13) {
  vm::Dictionary dict{16};
  for (std::size_t i = 0; i < pairs.size(); ++i) {
    vm::CellBuilder value;
    if (!(value.store_bits_bool(pairs[i].validator_id.value.cbits(), 256) &&
          value.store_long_bool(pairs[i].algorithm_id, 16) && value.store_ref_bool(pairs[i].signature) &&
          dict.set_builder(td::BitArray<16>{static_cast<unsigned>(i)}, value, vm::Dictionary::SetMode::Add))) {
      fail("PQ_SIGNATURE_PERSISTENCE_RAW_DICTIONARY_FAILED");
    }
  }
  vm::CellBuilder root;
  if (!(root.store_long_bool(tag, 8) && root.store_long_bool(validator_hash, 32) &&
        root.store_long_bool(catchain_seqno, 32) && root.store_long_bool(pairs.size(), 32) &&
        root.store_long_bool(weight, 64) && root.store_maybe_ref(std::move(dict).extract_root_cell()) &&
        root.store_bits_bool(session.cbits(), 256) && root.store_long_bool(slot, 32) &&
        root.store_ref_bool(std::move(candidate_data)))) {
    fail("PQ_SIGNATURE_PERSISTENCE_RAW_ROOT_FAILED");
  }
  return root.finalize_novm();
}

std::vector<RawPair> raw_pairs(const std::vector<block::PQBlockSignature>& pairs) {
  std::vector<RawPair> result;
  result.reserve(pairs.size());
  for (const auto& pair : pairs) {
    auto packed = require_ok(pq::pack_pq_bytes(pair.signature.as_slice(), pq::pq_bytes_hard_max), "pack-signature");
    result.push_back({pair.validator_id, static_cast<td::uint16>(pair.algorithm_id), std::move(packed)});
  }
  return result;
}

void expect_parse_error(td::Ref<vm::Cell> cell, td::Ref<block::ValidatorSet> validator_set, std::string_view expected,
                        std::string_view name) {
  expect_error(block::BlockSignatureSet::fetch(std::move(cell), std::move(validator_set)), expected, name);
  std::fprintf(stderr, "PQ_SIGNATURE_CORRUPTION_OK case=%.*s reason=%.*s\n", static_cast<int>(name.size()), name.data(),
               static_cast<int>(expected.size()), expected.data());
}

void expect_verify_error(td::Ref<vm::Cell> cell, const block::PQFinalityVerificationContext& context,
                         std::string_view expected, std::string_view name) {
  auto parsed = require_ok(block::BlockSignatureSet::fetch(std::move(cell), context.validator_set), name);
  expect_error(block::verify_pq_finality(context, *parsed, block::FinalityRole::Final), expected, name);
  std::fprintf(stderr, "PQ_SIGNATURE_CORRUPTION_OK case=%.*s reason=%.*s\n", static_cast<int>(name.size()), name.data(),
               static_cast<int>(expected.size()), expected.data());
}

void run_corruption_matrix() {
  Fixture fixture;
  const std::vector<std::size_t> signers{0, 1, 2};
  auto candidate_data = candidate(fixture.id);
  auto pairs = fixture.sign(signers, fixture.session, Fixture::slot, candidate_data, true, fixture.id);
  auto entries = raw_pairs(pairs);
  const auto weight = fixture.weight_of(signers);
  const auto context = block::PQFinalityVerificationContext{fixture.validator_set, fixture.id, fixture.session};
  const auto make_root = [&](const std::vector<RawPair>& values, ValidatorWeight claimed_weight,
                             ValidatorSessionId session, td::uint32 slot, td::Ref<vm::Cell> candidate_root,
                             unsigned tag = 0x13) {
    return raw_signature_set(values, fixture.validator_set->get_validator_set_hash(), Fixture::catchain_seqno,
                             claimed_weight, session, slot, std::move(candidate_root), tag);
  };

  expect_parse_error(make_root(entries, weight, fixture.session, Fixture::slot, candidate_cell(candidate_data), 0x12),
                     fixture.validator_set, "unsupported carrier for post-quantum validator set", "constructor");

  auto wrong_id = entries;
  wrong_id[0].validator_id.value.as_slice()[0] ^= 1;
  expect_parse_error(make_root(wrong_id, weight, fixture.session, Fixture::slot, candidate_cell(candidate_data)),
                     fixture.validator_set, "pq signatures: unknown validator_id", "validator_id");

  auto wrong_algorithm = entries;
  wrong_algorithm[0].algorithm_id ^= 1;
  expect_parse_error(make_root(wrong_algorithm, weight, fixture.session, Fixture::slot, candidate_cell(candidate_data)),
                     fixture.validator_set, "pq signatures: unsupported algorithm", "algorithm_id");

  auto wrong_length = entries;
  auto short_bytes = pairs[0].signature.clone();
  short_bytes.truncate(short_bytes.size() - 1);
  wrong_length[0].signature =
      require_ok(pq::pack_pq_bytes(short_bytes.as_slice(), pq::pq_bytes_hard_max), "pack-short-signature");
  expect_parse_error(make_root(wrong_length, weight, fixture.session, Fixture::slot, candidate_cell(candidate_data)),
                     fixture.validator_set, "pq signatures: signature length 2419, expected 2420", "pqbytes_length");

  auto wrong_signature = clone_pairs(pairs);
  wrong_signature[0].signature.as_slice()[100] ^= 1;
  expect_verify_error(
      make_root(raw_pairs(wrong_signature), weight, fixture.session, Fixture::slot, candidate_cell(candidate_data)),
      context, "pq signatures: invalid signature", "signature_chunk");

  auto wrong_session = fixture.session;
  wrong_session.as_slice()[0] ^= 1;
  expect_verify_error(make_root(entries, weight, wrong_session, Fixture::slot, candidate_cell(candidate_data)), context,
                      "carried session_id does not match trusted expected session_id", "session_id");

  expect_verify_error(make_root(entries, weight, fixture.session, Fixture::slot ^ 1, candidate_cell(candidate_data)),
                      context, "pq signatures: invalid signature", "slot");

  auto candidate_bytes = serialize_tl_object(candidate_data, true);
  candidate_bytes.as_slice().back() ^= 1;
  auto wrong_candidate = require_ok(vm::CellString::create(candidate_bytes.as_slice()), "wrong-candidate-cell");
  expect_verify_error(make_root(entries, weight, fixture.session, Fixture::slot, std::move(wrong_candidate)), context,
                      "pq signatures: invalid signature", "candidate_data");

  expect_parse_error(make_root(entries, weight - 1, fixture.session, Fixture::slot, candidate_cell(candidate_data)),
                     fixture.validator_set, "signature weight mismatch", "claimed_weight");
}

td::Ref<vm::Cell> block_proof_cell(const BlockIdExt& block_id, td::Ref<vm::Cell> signatures) {
  auto block_root = vm::CellBuilder{}.store_long(0x11ef55aa, 32).finalize_novm();
  if (RootHash{block_root->get_hash().bits()} != block_id.root_hash) {
    fail("PQ_SIGNATURE_PERSISTENCE_BLOCK_ROOT_MISMATCH");
  }
  auto merkle_proof =
      require_ok(vm::MerkleProof::generate(block_root, [](const td::Ref<vm::Cell>&) { return false; }), "merkle-proof");
  vm::CellBuilder builder;
  if (!(builder.store_long_bool(0xc3, 8) && block::tlb::t_BlockIdExt.pack(builder, block_id) &&
        builder.store_ref_bool(std::move(merkle_proof)) && builder.store_bool_bool(true) &&
        builder.store_ref_bool(std::move(signatures)))) {
    fail("PQ_SIGNATURE_PERSISTENCE_BLOCK_PROOF_BUILD_FAILED");
  }
  return builder.finalize_novm();
}

td::Ref<vm::Cell> ext_block_ref(const BlockIdExt& id) {
  vm::CellBuilder builder;
  if (!(builder.store_long_bool(id.seqno() * 1000ULL, 64) && builder.store_long_bool(id.seqno(), 32) &&
        builder.store_bits_bool(id.root_hash.cbits(), 256) && builder.store_bits_bool(id.file_hash.cbits(), 256))) {
    fail("PQ_TOP_BLOCK_DESCR_EXT_REF_BUILD_FAILED");
  }
  return builder.finalize_novm();
}

struct ShardProofFixture {
  BlockIdExt block_id;
  BlockIdExt previous_block_id;
  BlockIdExt governing_mc_block_id;
  td::Ref<vm::Cell> proof;
};

ShardProofFixture shard_proof_fixture(td::uint32 validator_set_hash, CatchainSeqno catchain_seqno) {
  const BlockIdExt governing{masterchainId, shardIdAll, 17, hash_of("top-descr-governing-a-root"),
                             hash_of("top-descr-governing-a-file")};
  const BlockIdExt previous{0, shardIdAll, 41, hash_of("top-descr-prev-root"), hash_of("top-descr-prev-file")};
  block::gen::BlockInfo::Record info;
  info.version = 0;
  info.not_master = true;
  info.after_merge = info.before_split = info.after_split = false;
  info.want_split = info.want_merge = false;
  info.key_block = info.vert_seqno_incr = false;
  info.flags = 0;
  info.seq_no = 42;
  info.vert_seq_no = 0;
  vm::CellBuilder shard;
  block::ShardId{ShardIdFull{0, shardIdAll}}.serialize(shard);
  info.shard = shard.as_cellslice_ref();
  info.gen_utime = 1000;
  info.start_lt = 42000;
  info.end_lt = 42001;
  info.gen_validator_list_hash_short = validator_set_hash;
  info.gen_catchain_seqno = catchain_seqno;
  info.min_ref_mc_seqno = governing.seqno();
  info.prev_key_block_seqno = governing.seqno();
  info.master_ref = ext_block_ref(governing);
  info.prev_ref = ext_block_ref(previous);
  td::Ref<vm::Cell> info_cell;
  if (!block::gen::t_BlockInfo.cell_pack(info_cell, info)) {
    fail("PQ_TOP_BLOCK_DESCR_INFO_BUILD_FAILED");
  }

  block::ValueFlow flow{block::ValueFlow::SetZero{}};
  vm::CellBuilder flow_builder;
  if (!flow.store(flow_builder)) {
    fail("PQ_TOP_BLOCK_DESCR_VALUE_FLOW_BUILD_FAILED");
  }
  vm::CellBuilder empty_dictionary_builder;
  empty_dictionary_builder.store_bool_bool(false);
  auto empty_dictionary = empty_dictionary_builder.finalize_novm();
  block::gen::BlockExtra::Record extra;
  extra.in_msg_descr = empty_dictionary;
  extra.out_msg_descr = empty_dictionary;
  extra.account_blocks = empty_dictionary;
  vm::CellBuilder custom_builder;
  custom_builder.store_bool_bool(false);
  extra.custom = custom_builder.as_cellslice_ref();
  extra.created_by = hash_of("top-descr-creator");
  td::Ref<vm::Cell> extra_cell;
  if (!block::gen::t_BlockExtra.cell_pack(extra_cell, extra)) {
    fail("PQ_TOP_BLOCK_DESCR_EXTRA_BUILD_FAILED");
  }
  auto root = vm::CellBuilder{}
                  .store_long(0x11ef55aa, 32)
                  .store_long(-111, 32)
                  .store_ref(info_cell)
                  .store_ref(flow_builder.finalize())
                  .store_ref(empty_dictionary)
                  .store_ref(extra_cell)
                  .finalize_novm();
  auto data = require_ok(vm::std_boc_serialize(root, 31), "top-descr-block-boc");
  td::Bits256 file_hash;
  td::sha256(data.as_slice(), file_hash.as_slice());
  BlockIdExt block_id{0, shardIdAll, 42, td::Bits256{root->get_hash().bits()}, file_hash};
  auto proof = require_ok(vm::MerkleProof::generate(root, [](const td::Ref<vm::Cell>&) { return false; }),
                          "top-descr-merkle-proof");
  return {block_id, previous, governing, std::move(proof)};
}

td::Ref<vm::Cell> top_block_descr_cell(const BlockIdExt& block_id, td::Ref<vm::Cell> signatures,
                                       td::Ref<vm::Cell> proof) {
  vm::CellBuilder builder;
  if (!(builder.store_long_bool(0xd5, 8) && block::tlb::t_BlockIdExt.pack(builder, block_id) &&
        builder.store_bool_bool(true) && builder.store_ref_bool(std::move(signatures)) &&
        builder.store_long_bool(1, 8) && builder.store_ref_bool(std::move(proof)))) {
    fail("PQ_SIGNATURE_PERSISTENCE_TOP_DESCR_BUILD_FAILED");
  }
  auto root = builder.finalize_novm();
  if (!block::gen::t_TopBlockDescr.validate_ref(root)) {
    fail("PQ_SIGNATURE_PERSISTENCE_TOP_DESCR_SCHEMA_FAILED");
  }
  return root;
}

td::Ref<block::BlockSignatureSet> parse_structural(td::Ref<vm::Cell> root, ValidatorWeight& claimed_weight,
                                                   std::string_view name) {
  return require_ok(block::BlockSignatureSet::fetch(std::move(root), claimed_weight), name);
}

void expect_consumer_error(td::Ref<block::BlockSignatureSet> signatures, ValidatorWeight claimed_weight,
                           const block::PQFinalityVerificationContext& context, std::string_view expected,
                           std::string_view name) {
  expect_error(verify_pq_proof_signatures(context, *signatures, claimed_weight), expected, name);
  std::fprintf(stderr, "PQ_PROOF_CONSUMER_REJECT_OK case=%.*s reason=%.*s\n", static_cast<int>(name.size()),
               name.data(), static_cast<int>(expected.size()), expected.data());
}

void run_proof_consumers() {
  Fixture fixture;
  auto block_root = vm::CellBuilder{}.store_long(0x11ef55aa, 32).finalize_novm();
  fixture.id.root_hash = RootHash{block_root->get_hash().bits()};
  const std::vector<std::size_t> quorum{0, 1, 2};
  auto candidate_data = candidate(fixture.id);
  auto pairs = fixture.sign(quorum, fixture.session, Fixture::slot, candidate_data, true, fixture.id);
  auto signatures =
      require_ok(block::BlockSignatureSet::create_simplex_pq_final(
                     clone_pairs(pairs), Fixture::catchain_seqno, fixture.validator_set->get_validator_set_hash(),
                     fixture.session, Fixture::slot, candidate(fixture.id)),
                 "consumer-carrier");
  auto signature_cell = require_ok(signatures->serialize(fixture.validator_set), "consumer-serialize");
  auto context = block::PQFinalityVerificationContext{fixture.validator_set, fixture.id, fixture.session};

  auto accepted_cell =
      require_ok(prepare_accepted_block_signatures(fixture.validator_set, signatures, fixture.id, fixture.session),
                 "accept-block-prepare");
  if (accepted_cell->get_hash() != signature_cell->get_hash()) {
    fail("PQ_ACCEPT_BLOCK_SIGNATURE_BYTES_MISMATCH");
  }
  auto wrong_expected_session = fixture.session;
  wrong_expected_session.as_slice()[0] ^= 1;
  expect_error(prepare_accepted_block_signatures(fixture.validator_set, signatures, fixture.id, wrong_expected_session),
               "carried session_id does not match trusted expected session_id", "accept_block_wrong_session");
  std::fprintf(stderr, "PQ_ACCEPT_BLOCK_BOUNDARY_OK\n");

  auto proof_root = block_proof_cell(fixture.id, signature_cell);
  auto proof_boc = require_ok(vm::std_boc_serialize(proof_root, 31), "proof-boc");
  auto proof_object = require_ok(create_proof(fixture.id, proof_boc.clone()), "proof-object");
  const auto proof_db_root = PSTRING() << "tmp-pq-block-proof-persistence-" << td::Random::fast_uint32();
  RootDbRoundTrip proof_db(proof_db_root);
  auto proof_handle = create_empty_block_handle(fixture.id);
  proof_db.store_proof(proof_handle, proof_object);
  auto persisted_proof = proof_db.load_proof(proof_handle);
  if (persisted_proof->data().as_slice() != proof_boc.as_slice()) {
    fail("PQ_BLOCK_PROOF_PERSISTENCE_BYTES_MISMATCH");
  }
  auto proof_loaded = require_ok(vm::std_boc_deserialize(persisted_proof->data()), "proof-load");
  auto proof_envelope = require_ok(parse_block_proof_signature_envelope(proof_loaded), "proof-envelope");
  if (proof_envelope.block_id != fixture.id || proof_envelope.signatures.is_null()) {
    fail("PQ_BLOCK_PROOF_ENVELOPE_ID_OR_SIGNATURES_MISMATCH");
  }
  require_ok(verify_pq_proof_signatures(context, *proof_envelope.signatures, proof_envelope.claimed_weight),
             "proof-verify");

  std::vector<ValidatorDescr> shard_descriptors;
  for (std::size_t i = 0; i < fixture.weights.size(); ++i) {
    shard_descriptors.push_back(fixture.descriptor(i));
  }
  auto shard_validator_set = td::Ref<block::ValidatorSet>{true, Fixture::catchain_seqno, ShardIdFull{0, shardIdAll},
                                                          std::move(shard_descriptors)};
  auto shard_proof = shard_proof_fixture(shard_validator_set->get_validator_set_hash(), Fixture::catchain_seqno);
  ValidatorSessionConfig session_options;
  session_options.new_catchain_ids = true;
  auto session_a = block::derive_validator_session_identity(
                       -111, block::validator_session_options_hash(session_options), hash_of("top-descr-param30-a"),
                       shard_proof.block_id.shard_full(), Fixture::catchain_seqno, shard_validator_set->export_vector(),
                       0, shard_proof.governing_mc_block_id.seqno(), true)
                       .session_id;
  auto session_b = block::derive_validator_session_identity(
                       -111, block::validator_session_options_hash(session_options), hash_of("top-descr-param30-b"),
                       shard_proof.block_id.shard_full(), Fixture::catchain_seqno, shard_validator_set->export_vector(),
                       0, shard_proof.governing_mc_block_id.seqno() + 1, true)
                       .session_id;
  auto shard_candidate = candidate(shard_proof.block_id);
  auto shard_pairs_a = fixture.sign(quorum, session_a, Fixture::slot, shard_candidate, true, shard_proof.block_id);
  auto shard_signatures_a =
      require_ok(block::BlockSignatureSet::create_simplex_pq_final(
                     clone_pairs(shard_pairs_a), Fixture::catchain_seqno, shard_validator_set->get_validator_set_hash(),
                     session_a, Fixture::slot, candidate(shard_proof.block_id)),
                 "top-descr-signatures-a");
  auto shard_signature_cell_a =
      require_ok(shard_signatures_a->serialize(shard_validator_set), "top-descr-signatures-a-serialize");
  auto top_root = top_block_descr_cell(shard_proof.block_id, shard_signature_cell_a, shard_proof.proof);
  auto top_boc = require_ok(vm::std_boc_serialize(top_root, 31), "top-descr-boc");
  auto top_loaded = require_ok(vm::std_boc_deserialize(top_boc.as_slice()), "top-descr-load");
  auto production_top = require_ok(ShardTopBlockDescrQ::fetch(top_loaded), "top-descr-production-fetch");
  if (production_top->governing_masterchain_block_id() != shard_proof.governing_mc_block_id) {
    fail("PQ_TOP_BLOCK_DESCR_GOVERNING_SNAPSHOT_MISMATCH");
  }
  const BlockIdExt current_after_key_block{masterchainId, shardIdAll, 18, hash_of("top-descr-current-b-root"),
                                           hash_of("top-descr-current-b-file")};
  auto shard_top = td::Ref<block::McShardHash>{true, shard_proof.previous_block_id, 41000, 41001};
  SelectedNewConsensusConfig selected_a{.config = {}, .cell_hash = hash_of("top-descr-param30-a")};
  SelectedNewConsensusConfig selected_b{.config = {}, .cell_hash = hash_of("top-descr-param30-b")};
  auto governing_state = td::Ref<FocusedMasterchainState>{true,
                                                          shard_proof.governing_mc_block_id,
                                                          -111,
                                                          0,
                                                          shard_proof.governing_mc_block_id,
                                                          shard_validator_set,
                                                          shard_top,
                                                          session_options,
                                                          selected_a,
                                                          std::vector<BlockIdExt>{}};
  auto current_state = td::Ref<FocusedMasterchainState>{true,
                                                        current_after_key_block,
                                                        -111,
                                                        0,
                                                        current_after_key_block,
                                                        shard_validator_set,
                                                        shard_top,
                                                        session_options,
                                                        selected_b,
                                                        std::vector<BlockIdExt>{shard_proof.governing_mc_block_id}};
  auto mismatched_global_id_state = td::Ref<FocusedMasterchainState>{true,
                                                                     shard_proof.governing_mc_block_id,
                                                                     -111,
                                                                     0,
                                                                     shard_proof.governing_mc_block_id,
                                                                     shard_validator_set,
                                                                     shard_top,
                                                                     session_options,
                                                                     selected_a,
                                                                     std::vector<BlockIdExt>{},
                                                                     -112};

  int res_flags = 0;
  require_ok(production_top->prevalidate(shard_proof.governing_mc_block_id, governing_state, governing_state,
                                         ShardTopBlockDescrQ::fail_new | ShardTopBlockDescrQ::fail_too_new, res_flags),
             "top-descr-validate-at-governing-state");
  res_flags = 0;
  require_ok(production_top->prevalidate(current_after_key_block, current_state, governing_state,
                                         ShardTopBlockDescrQ::fail_new | ShardTopBlockDescrQ::fail_too_new, res_flags),
             "top-descr-validate-after-key-block-with-governing-state");
  res_flags = 0;
  expect_error(
      production_top->prevalidate(current_after_key_block, current_state, mismatched_global_id_state,
                                  ShardTopBlockDescrQ::fail_new | ShardTopBlockDescrQ::fail_too_new, res_flags),
      "governing state global_id -111 disagrees with ConfigParam 19 global_id -112",
      "top_descr_global_id_disagreement");
  auto mismatched_config = require_ok(mismatched_global_id_state->get_config_holder(), "mismatched-config-holder");
  expect_error(derive_pq_finality_context(*mismatched_config, shard_validator_set, shard_proof.block_id, 0,
                                          shard_proof.governing_mc_block_id.seqno()),
               "governing state global_id -111 disagrees with ConfigParam 19 global_id -112",
               "config_holder_global_id_disagreement");
  res_flags = 0;
  expect_error(
      production_top->prevalidate(current_after_key_block, current_state, current_state,
                                  ShardTopBlockDescrQ::fail_new | ShardTopBlockDescrQ::fail_too_new, res_flags),
      "top block description governing state mismatch", "top_descr_current_state_is_not_governing");
  auto top_envelope = require_ok(parse_top_block_descr_signature_envelope(top_loaded), "top-descr-envelope");
  if (top_envelope.block_id != shard_proof.block_id || top_envelope.signatures.is_null() ||
      top_envelope.signatures->get_catchain_seqno() != Fixture::catchain_seqno ||
      top_envelope.signatures->get_validator_set_hash() != shard_validator_set->get_validator_set_hash()) {
    fail("PQ_TOP_BLOCK_DESCR_ENVELOPE_METADATA_MISMATCH");
  }
  const block::PQFinalityVerificationContext governing_context{shard_validator_set, shard_proof.block_id, session_a};
  require_ok(verify_pq_proof_signatures(governing_context, *top_envelope.signatures, top_envelope.claimed_weight),
             "top-descr-verify");

  auto shard_pairs_b =
      fixture.sign(quorum, session_b, Fixture::slot, candidate(shard_proof.block_id), true, shard_proof.block_id);
  auto shard_signatures_b =
      require_ok(block::BlockSignatureSet::create_simplex_pq_final(
                     clone_pairs(shard_pairs_b), Fixture::catchain_seqno, shard_validator_set->get_validator_set_hash(),
                     session_b, Fixture::slot, candidate(shard_proof.block_id)),
                 "top-descr-signatures-b");
  auto shard_signature_cell_b =
      require_ok(shard_signatures_b->serialize(shard_validator_set), "top-descr-signatures-b-serialize");
  auto post_change_root = top_block_descr_cell(shard_proof.block_id, shard_signature_cell_b, shard_proof.proof);
  auto post_change_top = require_ok(ShardTopBlockDescrQ::fetch(post_change_root), "top-descr-post-change-fetch");
  res_flags = 0;
  expect_error(
      post_change_top->prevalidate(current_after_key_block, current_state, governing_state,
                                   ShardTopBlockDescrQ::fail_new | ShardTopBlockDescrQ::fail_too_new, res_flags),
      "carried session_id does not match trusted expected session_id", "top_descr_post_change_session");
  std::fprintf(stderr, "PQ_TOP_BLOCK_DESCR_GOVERNING_SNAPSHOT_OK pre_change=accepted post_change=refused\n");
  std::fprintf(stderr, "PQ_BLOCK_PROOF_ROUNDTRIP_OK bytes=%zu\n", proof_boc.size());
  std::fprintf(stderr, "PQ_TOP_BLOCK_DESCR_ROUNDTRIP_OK bytes=%zu\n", top_boc.size());

  auto legacy = block::BlockSignatureSet::create_ordinary({}, Fixture::catchain_seqno,
                                                          fixture.validator_set->get_validator_set_hash());
  expect_consumer_error(legacy, 0, context, "post-quantum carrier required", "classical_under_pq_set");

  auto entries = raw_pairs(pairs);
  const auto weight = fixture.weight_of(quorum);
  const auto raw = [&](td::uint32 validator_hash, CatchainSeqno cc, ValidatorWeight claimed,
                       const std::vector<RawPair>& values, td::Ref<vm::Cell> candidate_root) {
    return raw_signature_set(values, validator_hash, cc, claimed, fixture.session, Fixture::slot,
                             std::move(candidate_root));
  };
  ValidatorWeight claimed = 0;
  auto wrong_hash = parse_structural(raw(fixture.validator_set->get_validator_set_hash() ^ 1, Fixture::catchain_seqno,
                                         weight, entries, candidate_cell(candidate_data)),
                                     claimed, "wrong-hash-parse");
  expect_consumer_error(wrong_hash, claimed, context, "validator set hash mismatch", "wrong_validator_set_hash");

  auto wrong_cc = parse_structural(raw(fixture.validator_set->get_validator_set_hash(), Fixture::catchain_seqno ^ 1,
                                       weight, entries, candidate_cell(candidate_data)),
                                   claimed, "wrong-cc-parse");
  expect_consumer_error(wrong_cc, claimed, context, "catchain seqno mismatch", "wrong_catchain_seqno");

  auto other_id = fixture.id;
  other_id.root_hash.as_slice()[0] ^= 1;
  expect_consumer_error(proof_envelope.signatures, proof_envelope.claimed_weight,
                        {fixture.validator_set, other_id, fixture.session}, "block id mismatch", "wrong_block_id");

  auto damaged = clone_pairs(pairs);
  damaged[0].signature.as_slice()[200] ^= 1;
  auto damaged_set = parse_structural(raw(fixture.validator_set->get_validator_set_hash(), Fixture::catchain_seqno,
                                          weight, raw_pairs(damaged), candidate_cell(candidate_data)),
                                      claimed, "damaged-signature-parse");
  expect_consumer_error(damaged_set, claimed, context, "pq signatures: invalid signature", "invalid_signature");

  std::vector<std::size_t> minority{3};
  auto minority_pairs = fixture.sign(minority, fixture.session, Fixture::slot, candidate_data, true, fixture.id);
  auto minority_set =
      parse_structural(raw(fixture.validator_set->get_validator_set_hash(), Fixture::catchain_seqno,
                           fixture.weight_of(minority), raw_pairs(minority_pairs), candidate_cell(candidate_data)),
                       claimed, "sub-quorum-parse");
  expect_consumer_error(minority_set, claimed, context, "pq signatures: insufficient verified weight", "sub_quorum");

  auto wrong_weight = parse_structural(raw(fixture.validator_set->get_validator_set_hash(), Fixture::catchain_seqno,
                                           weight - 1, entries, candidate_cell(candidate_data)),
                                       claimed, "wrong-weight-parse");
  expect_consumer_error(wrong_weight, claimed, context, "bad signature set weight", "claimed_weight_mismatch");
}

void run_round_trip(std::size_t signer_count, td::uint32 discriminator) {
  LargeFixture fixture(signer_count, discriminator);
  auto signatures = fixture.signatures();
  auto before_cell = require_ok(signatures->serialize(fixture.validator_set), "serialize-before");
  auto before = require_ok(vm::std_boc_serialize(before_cell, 31), "boc-before");

  const auto root = PSTRING() << "tmp-pq-signature-persistence-" << signer_count << "-" << td::Random::fast_uint32();
  RootDbRoundTrip db(root);
  auto handle = create_empty_block_handle(fixture.id);
  db.store(handle, signatures, fixture.validator_set);
  auto loaded = db.load(handle);

  auto after_cell = require_ok(loaded->serialize(fixture.validator_set), "serialize-after");
  auto after = require_ok(vm::std_boc_serialize(after_cell, 31), "boc-after");
  if (before.as_slice() != after.as_slice()) {
    fail(PSTRING() << "PQ_SIGNATURE_PERSISTENCE_BYTES_MISMATCH signers=" << signer_count);
  }
  block::PQFinalityVerificationContext context{fixture.validator_set, fixture.id, fixture.session};
  auto weight = require_ok(block::verify_pq_finality(context, *loaded, block::FinalityRole::Final), "verify-after");
  if (weight != signer_count) {
    fail(PSTRING() << "PQ_SIGNATURE_PERSISTENCE_WEIGHT_MISMATCH signers=" << signer_count << " actual=" << weight);
  }
  std::fprintf(stderr, "PQ_SIGNATURE_PERSISTENCE_OK signers=%zu bytes=%zu\n", signer_count, before.size());
}

}  // namespace

int main() {
  run_round_trip(21, 21);
  run_round_trip(100, 100);
  run_corruption_matrix();
  run_proof_consumers();
  return 0;
}
