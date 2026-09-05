#include <atomic>
#include <random>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/workchain-block-execution.h"
#include "td/actor/actor.h"
#include "td/utils/port/path.h"
#include "td/utils/tests.h"
#include "uno/core/used-nullifiers.h"
#include "validator/downloaders/download-state.hpp"
#include "validator/state-serializer.hpp"
#include "validator/streaming-import-budget.h"
#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"

namespace {
class SnapshotImportActor final : public td::actor::Actor {
 public:
  SnapshotImportActor(std::string directory, tos::validator::PersistentStateImportRequest request,
                      td::Bits256 expected_payload, std::vector<td::Bits256> keys, std::atomic<bool>& completed,
                      bool reopen = false)
      : directory_(std::move(directory))
      , request_(std::move(request))
      , expected_payload_(expected_payload)
      , keys_(std::move(keys))
      , completed_(completed)
      , reopen_(reopen) {
  }

  void start_up() override {
    alarm_timestamp() = td::Timestamp::in(30);
    auto options = tos::validator::ValidatorManagerOptions::create({}, {});
    options.write().set_celldb_in_memory(false);
    options.write().set_celldb_v2(false);
    options.write().set_disable_rocksdb_stats(true);
    database_ = td::actor::create_actor<tos::validator::CellDb>(
        "uno-snapshot-celldb", td::actor::ActorId<tos::validator::RootDb>{}, directory_, options);
    if (reopen_) {
      td::actor::send_closure(database_, &tos::validator::CellDb::load_cell, request_.expected_root_hash,
                              [self = actor_id(this)](td::Result<td::Ref<vm::DataCell>> root) mutable {
                                td::actor::send_closure(self, &SnapshotImportActor::reloaded, std::move(root));
                              });
      return;
    }
    auto wrong = request_;
    wrong.expected_root_hash.as_slice()[0] ^= 1;
    td::actor::send_closure(
        database_, &tos::validator::CellDb::import_persistent_state_streaming, std::move(wrong),
        [self = actor_id(this)](td::Result<tos::validator::PersistentStateImportResult> result) mutable {
          td::actor::send_closure(self, &SnapshotImportActor::rejected, std::move(result));
        });
  }
  void rejected(td::Result<tos::validator::PersistentStateImportResult> result) {
    ASSERT_TRUE(result.is_error());
    if (attempt_++ == 0) {
      ASSERT_TRUE(result.error().message().str().find("spool budget exceeded") != std::string::npos);
      // Restore the ordinary per-import cap after testing explicit rejection.
      auto config = tos::validator::fullnode::persistent_state_budget_config();
      config.max_spool_bytes_per_import =
          tos::validator::fullnode::PersistentStateBudgetConfig{}.max_spool_bytes_per_import;
      tos::validator::fullnode::configure_persistent_state_budgets(config);
      auto wrong = request_;
      wrong.expected_root_hash.as_slice()[0] ^= 1;
      td::actor::send_closure(
          database_, &tos::validator::CellDb::import_persistent_state_streaming, std::move(wrong),
          [self = actor_id(this)](td::Result<tos::validator::PersistentStateImportResult> retried) mutable {
            td::actor::send_closure(self, &SnapshotImportActor::rejected, std::move(retried));
          });
      return;
    }
    // The following successful import of the identical bytes and budgets
    // rules out fixture/budget rejection without relying on error wording.
    td::actor::send_closure(
        database_, &tos::validator::CellDb::import_persistent_state_streaming, request_,
        [self = actor_id(this)](td::Result<tos::validator::PersistentStateImportResult> imported) mutable {
          td::actor::send_closure(self, &SnapshotImportActor::accepted, std::move(imported));
        });
  }
  void accepted(td::Result<tos::validator::PersistentStateImportResult> result) {
    auto imported = result.move_as_ok();
    ASSERT_TRUE(imported.cells_persisted > keys_.size());
    ASSERT_TRUE(imported.gc_lease != nullptr);
    ASSERT_TRUE(td::Bits256(imported.hash_only_root->get_hash().bits()) == request_.expected_root_hash);
    verify_root(imported.hash_only_root);
    lease_ = std::move(imported.gc_lease);
    // Synthetic block identity: exercise CellDb root registration, without
    // claiming validation of a block header or a network checkpoint.
    tos::BlockIdExt block_id{tos::BlockId{2, tos::shardIdAll, 1}};
    td::actor::send_closure(database_, &tos::validator::CellDb::store_cell, block_id,
                            std::move(imported.hash_only_root), vm::StoreCellHint{},
                            [self = actor_id(this)](td::Result<td::Ref<vm::DataCell>> root) mutable {
                              td::actor::send_closure(self, &SnapshotImportActor::stored, std::move(root));
                            });
  }
  void verify_root(td::Ref<vm::Cell> root) {
    ASSERT_TRUE(td::Bits256(root->get_hash().bits()) == request_.expected_root_hash);
    auto payload = block::extract_workchain_engine_state(root, 2, td::Bits256::zero()).move_as_ok();
    ASSERT_TRUE(td::Bits256(payload->get_hash().bits()) == expected_payload_);
    vm::Dictionary dictionary(payload, 256);
    for (const auto& key : keys_) {
      ASSERT_TRUE(dictionary.lookup(key).not_null());
    }
  }
  void stored(td::Result<td::Ref<vm::DataCell>> result) {
    verify_root(result.move_as_ok());
    ASSERT_TRUE(lease_->active());
    lease_->release_after_root_store_committed();
    ASSERT_TRUE(!lease_->active());
    // The reader request forwards through the same inner actor after release,
    // so its callback is also a barrier for the adoption/lease-release message.
    td::actor::send_closure(database_, &tos::validator::CellDb::get_cell_db_reader,
                            [self = actor_id(this)](td::Result<std::shared_ptr<vm::CellDbReader>> reader) mutable {
                              td::actor::send_closure(self, &SnapshotImportActor::read_after_release,
                                                      std::move(reader));
                            });
  }
  void read_after_release(td::Result<std::shared_ptr<vm::CellDbReader>> result) {
    auto reader = result.move_as_ok();
    verify_root(reader->load_cell(request_.expected_root_hash.as_slice()).move_as_ok());
    check_registration();
  }
  void reloaded(td::Result<td::Ref<vm::DataCell>> result) {
    verify_root(result.move_as_ok());
    check_registration();
  }
  void check_registration() {
    td::actor::send_closure(database_, &tos::validator::CellDb::get_registered_state_root,
                            tos::BlockIdExt{tos::BlockId{2, tos::shardIdAll, 1}},
                            [self = actor_id(this)](td::Result<tos::RootHash> root) mutable {
                              td::actor::send_closure(self, &SnapshotImportActor::registered, std::move(root));
                            });
  }
  void registered(td::Result<tos::RootHash> result) {
    ASSERT_TRUE(result.move_as_ok() == request_.expected_root_hash);
    completed_.store(true);
    td::actor::SchedulerContext::get().stop();
  }
  void alarm() override {
    ASSERT_TRUE(false);
  }

 private:
  std::string directory_;
  tos::validator::PersistentStateImportRequest request_;
  td::Bits256 expected_payload_;
  std::vector<td::Bits256> keys_;
  std::atomic<bool>& completed_;
  unsigned attempt_ = 0;
  bool reopen_ = false;
  std::unique_ptr<tos::validator::CellDbGcPauseLease> lease_;
  td::actor::ActorOwn<tos::validator::CellDb> database_;
};

void actor_import_snapshot(td::Ref<vm::Cell> state, td::Ref<vm::Cell> payload, const std::vector<td::Bits256>& keys) {
  auto bytes = vm::std_boc_serialize(state).move_as_ok();
  auto temporary = td::mkstemp("/tmp").move_as_ok();
  temporary.first.write_all(bytes.as_slice()).ensure();
  temporary.first.close();
  tos::validator::fullnode::BudgetedStateFile file(temporary.second, bytes.size(), {});
  auto directory = td::mkdtemp("/tmp", "uno-snapshot-celldb-").move_as_ok();
  LOG(INFO) << "UNO actor import database retained at " << directory;
  tos::validator::PersistentStateImportRequest request;
  request.tempfile_path = file.path;
  request.file_size = file.size;
  request.expected_root_hash = state->get_hash().bits();
  request.opts.max_resident_bytes = 16ULL << 20;
  auto saved_budget = tos::validator::fullnode::persistent_state_budget_config();
  auto default_ratio = saved_budget;
  default_ratio.spool_reservation_ratio_percent = 300;
  default_ratio.max_spool_bytes_per_import = 1;
  tos::validator::fullnode::configure_persistent_state_budgets(default_ratio);
  for (bool reopen : {false, true}) {
    std::atomic<bool> completed{false};
    td::actor::Scheduler scheduler({2});
    td::actor::ActorOwn<SnapshotImportActor> actor;
    scheduler.run_in_context([&] {
      actor = td::actor::create_actor<SnapshotImportActor>(
          "uno-snapshot-import", directory, request, td::Bits256(payload->get_hash().bits()), keys, completed, reopen);
    });
    scheduler.run();
    ASSERT_TRUE(completed.load());
  }
  tos::validator::fullnode::configure_persistent_state_budgets(saved_budget);
}

td::Ref<vm::Cell> import_snapshot_part(td::Ref<vm::Cell> cell) {
  auto bytes = vm::std_boc_serialize(cell).move_as_ok();
  auto temporary = td::mkstemp("/tmp").move_as_ok();
  temporary.first.write_all(bytes.as_slice()).ensure();
  temporary.first.close();
  tos::validator::fullnode::BudgetedStateFile file(temporary.second, bytes.size(), {});
  vm::StreamingBocImportOptions options;
  options.max_resident_bytes = 16ULL << 20;
  const tos::RootHash expected{cell->get_hash().bits()};
  tos::validator::fullnode::CellDbStreamingSink sink;
  auto imported = tos::validator::parse_ondisk_state_streaming(file, expected, options, &sink).move_as_ok();
  ASSERT_TRUE(sink.finished());
  ASSERT_TRUE(!sink.aborted());
  ASSERT_TRUE(sink.cell_count() > 1);
  ASSERT_EQ(sink.cells_persisted(), 0u);
  ASSERT_TRUE(imported->get_hash() == cell->get_hash());

  auto wrong_hash = expected;
  wrong_hash.as_slice()[0] ^= 1;
  tos::validator::fullnode::CellDbStreamingSink wrong_root_sink;
  ASSERT_TRUE(tos::validator::parse_ondisk_state_streaming(file, wrong_hash, options, &wrong_root_sink).is_error());
  // Parsing really completed: this rejection is the root binding, not a
  // malformed fixture or a resource error before root comparison.
  ASSERT_TRUE(wrong_root_sink.finished());
  ASSERT_EQ(wrong_root_sink.cell_count(), sink.cell_count());

  auto limited = options;
  limited.max_cells = 1;
  tos::validator::fullnode::CellDbStreamingSink limited_sink;
  ASSERT_TRUE(tos::validator::parse_ondisk_state_streaming(file, expected, limited, &limited_sink).is_error());
  ASSERT_EQ(limited_sink.cell_count(), 0u);
  ASSERT_TRUE(!limited_sink.finished());
  return imported;
}

td::Ref<vm::Cell> single_account_state(td::Ref<vm::Cell> engine) {
  const auto address = td::Bits256::zero();
  auto executor = block::encode_workchain_executor_state({engine, {}, {}}).move_as_ok();
  vm::CellBuilder account;
  account.store_long(1, 1)
      .store_long(4, 3)
      .store_long(2, 8)
      .store_bits(address.bits(), 256)
      .store_zeroes(42)
      .store_long(2, 64);
  ASSERT_TRUE(block::CurrencyCollection(0).store(account));
  account.store_long(1, 1).store_zeroes(3).store_long(1, 1).store_ref(executor).store_long(0, 1);
  auto account_root = account.finalize();
  ASSERT_TRUE(block::gen::t_Account.validate_ref(1000000, account_root));
  vm::CellBuilder entry;
  entry.store_ref(account_root).store_zeroes(256).store_long(1, 64);
  vm::AugmentedDictionary accounts(256, block::tlb::aug_ShardAccounts);
  ASSERT_TRUE(accounts.set_builder(address, entry));
  auto queue = vm::CellBuilder().store_zeroes(67).finalize();
  vm::CellBuilder aux;
  aux.store_zeroes(128);
  ASSERT_TRUE(block::CurrencyCollection(0).store(aux));
  auto root = vm::CellBuilder()
                  .store_long(0x9023afe2, 32)
                  .store_long(1, 32)
                  .store_long(0, 2)
                  .store_long(0, 6)
                  .store_long(2, 32)
                  .store_long(0, 64)
                  .store_long(1, 32)
                  .store_long(0, 32)
                  .store_long(1, 32)
                  .store_long(2, 64)
                  .store_long(0, 32)
                  .store_ref(queue)
                  .store_long(0, 1)
                  .store_ref(accounts.get_wrapped_dict_root())
                  .store_ref(aux.store_zeroes(7).finalize())
                  .store_long(0, 1)
                  .finalize();
  ASSERT_TRUE(block::gen::t_ShardStateUnsplit.validate_ref(1000000, root));
  return root;
}
}  // namespace

TEST(UnoStateSnapshot, EncodingBudgetCheckedArithmetic) {
  using tos::validator::streaming_import_encoding_bound;
  ASSERT_EQ(streaming_import_encoding_bound(100, 1).move_as_ok(), 1376u);
  ASSERT_EQ(streaming_import_encoding_bound(168133, 8198).move_as_ok(), 9977114u);
  ASSERT_TRUE(streaming_import_encoding_bound(0, 1).is_error());
  ASSERT_TRUE(streaming_import_encoding_bound(1, 0).is_error());
  constexpr auto max = std::numeric_limits<td::uint64>::max();
  ASSERT_TRUE(streaming_import_encoding_bound(1, max).is_error());
  ASSERT_TRUE(streaming_import_encoding_bound(max, 1).is_error());
  ASSERT_TRUE(streaming_import_encoding_bound(max / 2, 1).is_error());
}

TEST(UnoStateSnapshot, SingleAccountIsAnIndivisibleSnapshotPart) {
  // Reproducible synthetic keys, not cryptographic test vectors. Random-looking
  // paths avoid the excessive DAG sharing of a sequential integer key set.
  std::mt19937 generator(42);
  std::vector<td::Bits256> keys(4096);
  for (auto& key : keys) {
    for (auto& byte : key.as_slice()) {
      byte = static_cast<char>(generator() & 255);
    }
  }
  auto used = uno_workchain::UsedNullifiers{}.with_used(keys).move_as_ok();
  auto state = single_account_state(used.root());
  actor_import_snapshot(state, used.root(), keys);
  auto unsplit = tos::validator::split_shard_state(tos::shardIdAll, state, 0);
  ASSERT_EQ(unsplit.size(), 1u);
  ASSERT_TRUE(unsplit[0].type.has<tos::validator::UnsplitStateType>());
  ASSERT_TRUE(unsplit[0].cell->get_hash() == state->get_hash());
  for (int depth : {1, 4, 8}) {
    auto parts = tos::validator::split_shard_state(tos::shardIdAll, state, depth);
    ASSERT_EQ(parts.size(), 2u);
    ASSERT_TRUE(parts.back().type.has<tos::validator::SplitPersistentStateType>());
    auto header_bytes = vm::std_boc_serialize(parts.back().cell).move_as_ok();
    auto header_proof = vm::std_boc_deserialize(header_bytes.as_slice()).move_as_ok();
    auto header = vm::MerkleProof::virtualize(header_proof).move_as_ok();
    ASSERT_TRUE(header->get_hash() == state->get_hash());
    unsigned account_parts = 0, headers = 0;
    for (const auto& part : parts) {
      if (part.type.has<tos::validator::SplitPersistentStateType>()) {
        ++headers;
        continue;
      }
      ASSERT_TRUE(part.type.has<tos::validator::SplitAccountStateType>());
      ++account_parts;
      auto restored = import_snapshot_part(part.cell);
      ASSERT_TRUE(restored->get_hash() == part.cell->get_hash());
      block::gen::ShardStateUnsplit::Record decoded;
      ASSERT_TRUE(tlb::unpack_cell(header, decoded));
      decoded.accounts = restored;
      td::Ref<vm::Cell> reconstructed;
      ASSERT_TRUE(tlb::pack_cell(reconstructed, decoded));
      ASSERT_TRUE(reconstructed->get_hash() == state->get_hash());
      auto payload = block::extract_workchain_engine_state(reconstructed, 2, td::Bits256::zero()).move_as_ok();
      ASSERT_TRUE(payload->get_hash() == used.root()->get_hash());
      vm::Dictionary dictionary(payload, 256);
      for (const auto& key : keys) {
        ASSERT_TRUE(dictionary.lookup(key).not_null());
      }
    }
    ASSERT_EQ(account_parts, 1u);
    ASSERT_EQ(headers, 1u);
  }
}
