#include <atomic>
#include <cstdlib>
#include <random>
#include <condition_variable>
#include <mutex>
#include <chrono>
#include <iostream>
#include "rocksdb/merge_operator.h"

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/workchain-block-execution.h"
#include "td/actor/actor.h"
#include "td/utils/port/path.h"
#include "td/utils/tests.h"
#include "td/db/RocksDb.h"
#include "uno/core/used-nullifiers.h"
#include "validator/downloaders/download-state.hpp"
#include "validator/state-serializer.hpp"
#include "validator/streaming-import-budget.h"
#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"
#include "vm/db/CellStorage.h"
#include "vm/db/DynamicBagOfCellsDb.h"
#include "uno-snapshot-transport.h"
#ifdef TOS_UNO_STORAGE_MEASUREMENT
#include <sys/resource.h>
#include "crypto/test/workchain-counter-engine.h"
#include "block/transaction.h"
#endif

namespace {
class RetainedStateMergeOperator final : public rocksdb::MergeOperator {
 public:
  const char* Name() const override { return "RetainedStateMergeOperator"; }
  bool FullMergeV2(const MergeOperationInput& input, MergeOperationOutput* output) const override {
    if (!input.existing_value || input.operand_list.empty()) return false;
    auto diff = input.operand_list.front().ToString();
    for (std::size_t i = 1; i < input.operand_list.size(); ++i) {
      const auto& operand = input.operand_list[i];
      vm::CellStorer::merge_refcnt_diffs(diff, td::Slice(operand.data(), operand.size()));
    }
    output->new_value = input.existing_value->ToString();
    vm::CellStorer::merge_value_and_refcnt_diff(output->new_value, diff);
    return true;
  }
  bool PartialMerge(const rocksdb::Slice&, const rocksdb::Slice& left, const rocksdb::Slice& right,
                    std::string* output, rocksdb::Logger*) const override {
    *output = left.ToString();
    vm::CellStorer::merge_refcnt_diffs(*output, td::Slice(right.data(), right.size()));
    return true;
  }
};

class ImportAdmissionActor final : public td::actor::Actor {
 public:
  ImportAdmissionActor(std::string directory, tos::validator::PersistentStateImportRequest request,
                       td::uint64 bound, std::atomic<bool>& completed)
      : directory_(std::move(directory)), request_(std::move(request)), bound_(bound), completed_(completed) {}

  void start_up() override {
    auto options = tos::validator::ValidatorManagerOptions::create({}, {});
    options.write().set_celldb_in_memory(false);
    options.write().set_disable_rocksdb_stats(true);
    database_ = td::actor::create_actor<tos::validator::CellDb>(
        "admission-celldb", td::actor::ActorId<tos::validator::RootDb>{}, directory_, options);
    deadline_ = td::Timestamp::in(30);
    alarm_timestamp() = td::Timestamp::in(0.01);
    request_.opts.is_cancelled = [this] { entered_parse_.store(true); return false; };
    submit();
  }

  void submit() {
    td::actor::send_closure(database_, &tos::validator::CellDb::import_persistent_state_streaming, request_,
        [self = actor_id(this)](td::Result<tos::validator::PersistentStateImportResult> result) mutable {
          td::actor::send_closure(self, &ImportAdmissionActor::imported, std::move(result));
        });
  }

  void imported(td::Result<tos::validator::PersistentStateImportResult> result) {
    if (phase_ == 2) {
      auto value = result.move_as_ok();
      ASSERT_TRUE(value.cells_persisted > 0);
      ASSERT_TRUE(td::Bits256(value.hash_only_root->get_hash().bits()) == request_.expected_root_hash);
      ASSERT_TRUE(!request_.cancel_requested->load());
      completed_.store(true);
      td::actor::SchedulerContext::get().stop();
      return;
    }
    ASSERT_TRUE(result.is_error());
    if (phase_ == 0) {
      // No worker/parser was entered; its only write path is after that worker.
      ASSERT_TRUE(!entered_parse_.load());
    } else {
      ASSERT_TRUE(worker_blocked_.load());
      ASSERT_TRUE(request_.cancel_requested->load());
    }
    td::actor::send_closure(database_, &tos::validator::CellDb::get_cell_db_reader,
        [self = actor_id(this)](td::Result<std::shared_ptr<vm::CellDbReader>> reader) mutable {
          td::actor::send_closure(self, &ImportAdmissionActor::verify_no_root, std::move(reader));
        });
  }

  void verify_no_root(td::Result<std::shared_ptr<vm::CellDbReader>> reader) {
    ASSERT_TRUE(reader.move_as_ok()->load_cell(request_.expected_root_hash.as_slice()).is_error());
    if (phase_ == 0) {
      auto config = tos::validator::fullnode::persistent_state_budget_config();
      config.max_spool_bytes_per_import = bound_;
      tos::validator::fullnode::configure_persistent_state_budgets(config);
      phase_ = 1;
      request_.cancel_requested = std::make_shared<std::atomic<bool>>(false);
      request_.opts.is_cancelled = [this] {
        std::unique_lock<std::mutex> lock(mutex_);
        worker_blocked_.store(true);
        condition_.wait(lock, [this] { return released_; });
        // The shared request flag, not this instrumentation, must cancel parsing.
        return false;
      };
    } else {
      phase_ = 2;
      request_.cancel_requested = std::make_shared<std::atomic<bool>>(false);
      request_.opts.is_cancelled = {};
    }
    submit();
  }

  void alarm() override {
    ASSERT_TRUE(!deadline_.is_in_past());
    if (phase_ == 1 && worker_blocked_.load()) {
      request_.cancel_requested->store(true);
      {
        std::lock_guard<std::mutex> lock(mutex_);
        released_ = true;
      }
      condition_.notify_one();
    }
    alarm_timestamp() = td::Timestamp::in(0.01);
  }

 private:
  std::string directory_;
  tos::validator::PersistentStateImportRequest request_;
  td::uint64 bound_;
  std::atomic<bool>& completed_;
  std::atomic<bool> entered_parse_{false}, worker_blocked_{false};
  std::mutex mutex_;
  std::condition_variable condition_;
  bool released_ = false;
  unsigned phase_ = 0;
  td::Timestamp deadline_;
  td::actor::ActorOwn<tos::validator::CellDb> database_;
};

struct SnapshotPhaseMeasurements {
  double import_request_ms = 0, first_lookup_ms = 0, root_store_ms = 0;
  double reopen_root_ms = 0, reopen_validate_and_append_ms = 0;
};

using SnapshotClock = std::chrono::steady_clock;
double snapshot_elapsed_ms(SnapshotClock::time_point start) {
  return std::chrono::duration<double, std::milli>(SnapshotClock::now() - start).count();
}

class SnapshotImportActor final : public td::actor::Actor {
 public:
  SnapshotImportActor(std::string directory, tos::validator::PersistentStateImportRequest request,
                      td::Bits256 expected_payload, std::vector<td::Bits256> keys, std::atomic<bool>& completed,
                      bool reopen = false, bool celldb_v2 = false, SnapshotPhaseMeasurements* measurements = nullptr)
      : directory_(std::move(directory))
      , request_(std::move(request))
      , expected_payload_(expected_payload)
      , keys_(std::move(keys))
      , completed_(completed)
      , reopen_(reopen)
      , celldb_v2_(celldb_v2)
      , measurements_(measurements) {
  }

  void start_up() override {
    started_ = SnapshotClock::now();
    alarm_timestamp() = td::Timestamp::in(request_.file_size > (64ULL << 20) ? 1200 : 30);
    auto options = tos::validator::ValidatorManagerOptions::create({}, {});
    options.write().set_celldb_in_memory(false);
    options.write().set_celldb_v2(celldb_v2_);
    options.write().set_celldb_cache_size(64ULL << 20);
    options.write().set_celldb_cache_min_size(64ULL << 20);
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
    if (measurements_) {
      td::actor::send_closure(database_, &tos::validator::CellDb::import_persistent_state_streaming, request_,
          [self = actor_id(this)](td::Result<tos::validator::PersistentStateImportResult> result) mutable {
            td::actor::send_closure(self, &SnapshotImportActor::accepted, std::move(result));
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
    if (measurements_) measurements_->import_request_ms = snapshot_elapsed_ms(started_);
    report_residency("imported-before-traversal");
    ASSERT_TRUE(imported.cells_persisted > keys_.size());
    ASSERT_TRUE(imported.gc_lease != nullptr);
    ASSERT_TRUE(td::Bits256(imported.hash_only_root->get_hash().bits()) == request_.expected_root_hash);
    auto lookup_start = SnapshotClock::now();
    verify_root(imported.hash_only_root);
    if (measurements_) measurements_->first_lookup_ms = snapshot_elapsed_ms(lookup_start);
    report_residency("imported-after-traversal");
    lease_ = std::move(imported.gc_lease);
    // Synthetic block identity: exercise CellDb root registration, without
    // claiming validation of a block header or a network checkpoint.
    tos::BlockIdExt block_id{tos::BlockId{2, tos::shardIdAll, 1}};
    store_started_ = SnapshotClock::now();
    td::actor::send_closure(database_, &tos::validator::CellDb::store_cell, block_id,
                            std::move(imported.hash_only_root), vm::StoreCellHint{},
                            [self = actor_id(this)](td::Result<td::Ref<vm::DataCell>> root) mutable {
                              td::actor::send_closure(self, &SnapshotImportActor::stored, std::move(root));
                            });
  }
  void verify_root(td::Ref<vm::Cell> root) {
    ASSERT_TRUE(td::Bits256(root->get_hash().bits()) == request_.expected_root_hash);
    root->load_cell().ensure();
    auto payload = block::extract_workchain_engine_state(root, 2, td::Bits256::zero()).move_as_ok();
    ASSERT_TRUE(td::Bits256(payload->get_hash().bits()) == expected_payload_);
    vm::Dictionary dictionary(payload, 256);
    for (const auto& key : keys_) {
      ASSERT_TRUE(dictionary.lookup(key).not_null());
    }
  }
  void stored(td::Result<td::Ref<vm::DataCell>> result) {
    if (measurements_) measurements_->root_store_ms = snapshot_elapsed_ms(store_started_);
    report_residency("adopted-before-traversal");
    verify_root(result.move_as_ok());
    report_residency("adopted-after-traversal");
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
    report_residency("lease-released-before-traversal");
    verify_root(reader->load_cell(request_.expected_root_hash.as_slice()).move_as_ok());
    report_residency("lease-released-after-traversal");
    check_registration();
  }
  void reloaded(td::Result<td::Ref<vm::DataCell>> result) {
    auto root = result.move_as_ok();
    if (measurements_) measurements_->reopen_root_ms = snapshot_elapsed_ms(started_);
    auto validation_start = SnapshotClock::now();
    report_residency("reopened-before-traversal");
    verify_root(root);
    report_residency("reopened-after-traversal");
    auto payload = block::extract_workchain_engine_state(root, 2, td::Bits256::zero()).move_as_ok();
    auto restored = uno_workchain::UsedNullifiers::from_root(payload, keys_.size()).move_as_ok();
    ASSERT_TRUE(restored.with_used({keys_.front()}).is_error());
    auto fresh = td::Bits256::zero();
    ASSERT_TRUE(!restored.contains(fresh));
    auto next = restored.with_used({fresh}).move_as_ok();
    ASSERT_TRUE(next.contains(fresh));
    ASSERT_TRUE(!restored.contains(fresh));
    ASSERT_TRUE(restored.root()->get_hash() == payload->get_hash());
    if (measurements_) measurements_->reopen_validate_and_append_ms = snapshot_elapsed_ms(validation_start);
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
  void report_residency(const char* phase) const {
    LOG(WARNING) << "Snapshot residency phase=" << phase << " celldb_v2=" << celldb_v2_
                 << " live_data_cells=" << vm::DataCell::get_total_data_cells()
                 << " includes_source_and_all_process_owners=true";
  }
  std::string directory_;
  tos::validator::PersistentStateImportRequest request_;
  td::Bits256 expected_payload_;
  std::vector<td::Bits256> keys_;
  std::atomic<bool>& completed_;
  unsigned attempt_ = 0;
  bool reopen_ = false;
  bool celldb_v2_ = false;
  SnapshotPhaseMeasurements* measurements_ = nullptr;
  SnapshotClock::time_point started_, store_started_;
  std::unique_ptr<tos::validator::CellDbGcPauseLease> lease_;
  td::actor::ActorOwn<tos::validator::CellDb> database_;
};

void actor_import_snapshot(td::Ref<vm::Cell> state, td::Ref<vm::Cell> payload, const std::vector<td::Bits256>& keys,
                           bool celldb_v2 = false) {
  using namespace tos::validator::fullnode;
  auto saved_download_directory = get_persistent_state_tempfile_dir();
  set_persistent_state_tempfile_dir(td::mkdtemp("/tmp", "uno-state-acquisition-").move_as_ok());
  auto downloaded = download_uno_snapshot_state_over_tcp(vm::std_boc_serialize(state).move_as_ok()).move_as_ok();
  set_persistent_state_tempfile_dir(saved_download_directory);
  BudgetedStateFile file;
  if (downloaded.is_file()) {
    // Preserve the downloader's exact file and reservation through database adoption.
    file = std::move(downloaded.file());
  } else {
    auto temporary = td::mkstemp("/tmp").move_as_ok();
    temporary.first.write_all(downloaded.memory().data.as_slice()).ensure();
    temporary.first.close();
    file = BudgetedStateFile(temporary.second, downloaded.memory().data.size(), {});
  }
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
          "uno-snapshot-import", directory, request, td::Bits256(payload->get_hash().bits()), keys, completed, reopen,
          celldb_v2);
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

#ifdef TOS_UNO_STORAGE_MEASUREMENT
namespace {
std::vector<td::Bits256> measurement_keys(std::size_t count) {
  std::mt19937 random(91);
  std::vector<td::Bits256> keys(count);
  for (auto& key : keys) {
    for (auto& byte : key.as_slice()) byte = static_cast<char>(random());
  }
  return keys;
}

struct MeasuredStateCells {
  td::uint64 batch_data, serialized_account;
};

td::Result<MeasuredStateCells> admit_measured_state(const uno_workchain::UsedNullifiers& used) {
  block::WorkchainBlockInput input{
      single_account_state(block::test::counter_number(40)), block::test::counter_number(2),
      block::test::counter_number(1), block::test::counter_number(1)};
  TRY_RESULT(effects, block::test::CounterEngine().execute_block(input));
  effects.new_engine_state = used.root();
  block::gen::ShardStateUnsplit::Record state;
  if (!tlb::unpack_cell(input.previous_shard_state, state)) return td::Status::Error("measurement shard");
  vm::AugmentedDictionary accounts(vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts);
  block::Account account(2, td::Bits256::zero().bits());
  if (!account.unpack(accounts.lookup(td::Bits256::zero()), 10, block::kWorkchainExecutorIsSpecial)) {
    return td::Status::Error("measurement account");
  }
  block::SerializeConfig cfg;
  cfg.global_version = block::kBlockTransitionMinGlobalVersion;
  cfg.size_limits.max_acc_state_cells = 65536;
  block::transaction::Transaction tx(account, block::transaction::Transaction::tr_workchain_batch, 10, 10);
  TRY_STATUS(tx.prepare_workchain_batch(input, effects, cfg));
  if (!tx.serialize(cfg)) return td::Status::Error("measurement batch serialization");
  vm::CellStorageStat stat;
  TRY_RESULT(depth, stat.compute_used_storage(tx.new_data));
  (void)depth;
  const auto data_cells = stat.cells;
  TRY_RESULT(account_depth, stat.compute_used_storage(tx.new_total_state));
  (void)account_depth;
  return MeasuredStateCells{data_cells, stat.cells};
}

long snapshot_peak_rss_kib() {
  struct rusage usage{};
  ASSERT_EQ(getrusage(RUSAGE_SELF, &usage), 0);
  ASSERT_TRUE(usage.ru_maxrss >= 0);
  return usage.ru_maxrss;
}
}  // namespace

TEST(UnoStorageMeasurement, CapacityGateInstrumentSelfCheck) {
  auto keys = measurement_keys(32768);
  auto oversized = uno_workchain::UsedNullifiers{}.with_used(keys).move_as_ok();
  auto rejected = admit_measured_state(oversized);
  ASSERT_TRUE(rejected.is_error());
  ASSERT_EQ(rejected.error().code(), block::AccountStorageStat::errorcode_limits_exceeded);
  keys.resize(32000);
  auto accepted = uno_workchain::UsedNullifiers{}.with_used(keys).move_as_ok();
  ASSERT_TRUE(admit_measured_state(accepted).is_ok());
}

TEST(UnoStorageMeasurement, SnapshotStages) {
  const char* requested = std::getenv("TOS_UNO_STORAGE_KEYS");
  ASSERT_TRUE(requested != nullptr);
  const std::string value(requested);
  const std::size_t count = value == "1000" ? 1000 : value == "8000" ? 8000 : value == "32000" ? 32000 : 0;
  ASSERT_TRUE(count != 0);
  const auto rss_before = snapshot_peak_rss_kib();
  auto started = SnapshotClock::now();
  auto keys = measurement_keys(count);
  auto used = uno_workchain::UsedNullifiers{}.with_used(keys).move_as_ok();
  auto state = single_account_state(used.root());
  const auto generate_ms = snapshot_elapsed_ms(started);
  started = SnapshotClock::now();
  const auto admitted_cells = admit_measured_state(used).move_as_ok();
  const auto host_admission_ms = snapshot_elapsed_ms(started);
  const auto rss_generated = snapshot_peak_rss_kib();
  started = SnapshotClock::now();
  auto bytes = vm::std_boc_serialize(state).move_as_ok();
  const auto serialize_ms = snapshot_elapsed_ms(started);
  const auto rss_serialized = snapshot_peak_rss_kib();
  vm::BagOfCells::Info info;
  ASSERT_TRUE(info.parse_serialized_header(bytes.as_slice()) > 0);
  auto file = td::mkstemp("/tmp").move_as_ok();
  file.first.write_all(bytes.as_slice()).ensure();
  file.first.close();
  const auto directory = td::mkdtemp("/tmp", "uno-storage-measurement-").move_as_ok();
  LOG(WARNING) << "Storage measurement database " << directory << " input " << file.second
               << " (removed on success, retained on failure)";
  tos::validator::PersistentStateImportRequest request;
  request.tempfile_path = file.second;
  request.file_size = bytes.size();
  request.expected_root_hash = state->get_hash().bits();
  request.opts.max_resident_bytes = 16ULL << 20;
  SnapshotPhaseMeasurements measurements;
  double whole_import_ms = 0, whole_reopen_ms = 0;
  long rss_imported = 0, rss_reopened = 0;
  for (bool reopen : {false, true}) {
    std::atomic<bool> completed{false};
    started = SnapshotClock::now();
    {
      td::actor::Scheduler scheduler({2});
      td::actor::ActorOwn<SnapshotImportActor> actor;
      scheduler.run_in_context([&] {
        actor = td::actor::create_actor<SnapshotImportActor>("storage-measurement", directory, request,
            td::Bits256(used.root()->get_hash().bits()), keys, completed, reopen, true, &measurements);
      });
      scheduler.run();
    }
    ASSERT_TRUE(completed.load());
    if (reopen) {
      whole_reopen_ms = snapshot_elapsed_ms(started);
      rss_reopened = snapshot_peak_rss_kib();
    } else {
      whole_import_ms = snapshot_elapsed_ms(started);
      rss_imported = snapshot_peak_rss_kib();
    }
  }
  std::cout << "STORAGE_CSV," << count << ",91," << info.cell_count << ',' << bytes.size() << ','
            << admitted_cells.batch_data << ',' << admitted_cells.serialized_account << ','
            << generate_ms << ',' << host_admission_ms << ',' << serialize_ms << ','
            << measurements.import_request_ms << ',' << measurements.first_lookup_ms << ','
            << measurements.root_store_ms << ',' << measurements.reopen_root_ms << ','
            << measurements.reopen_validate_and_append_ms << ',' << whole_import_ms << ',' << whole_reopen_ms << ','
            << rss_before << ',' << rss_generated << ',' << rss_serialized << ',' << rss_imported << ',' << rss_reopened
            << ',' << state->get_hash().to_hex() << std::endl;
  td::rmrf(directory).ensure();
  td::unlink(file.second).ensure();
}
#endif

TEST(UnoStateSnapshot, GrowingStateRetainsSharedCellsAfterRootRelease) {
  const auto directory = td::mkdtemp("/tmp", "uno-root-retention-").move_as_ok();
  LOG(WARNING) << "Root retention database: " << directory << " (removed on success, retained on failure)";
  std::unique_ptr<td::RocksDb> kv;
  std::unique_ptr<vm::DynamicBagOfCellsDb> database;
  auto reopen = [&] {
    database.reset();
    kv.reset();
    td::RocksDbOptions options;
    options.merge_operator = std::make_shared<RetainedStateMergeOperator>();
    kv = std::make_unique<td::RocksDb>(td::RocksDb::open(directory + "/cells", options).move_as_ok());
    database = vm::DynamicBagOfCellsDb::create_v2({.extra_threads = 0});
    database->set_loader(std::make_unique<vm::CellLoader>(kv->snapshot()));
  };
  auto commit = [&] {
    database->prepare_commit().ensure();
    kv->begin_write_batch().ensure();
    vm::CellStorer storer(*kv);
    database->commit(storer).ensure();
    kv->commit_write_batch().ensure();
  };
  reopen();
  std::mt19937 generator(91);
  std::vector<td::Bits256> keys;
  std::vector<vm::CellHash> retained, released;
  for (unsigned epoch = 0; epoch < 12; ++epoch) {
    {
      uno_workchain::UsedNullifiers previous;
      if (!retained.empty()) {
        auto state = database->load_cell(retained.back().as_slice()).move_as_ok();
        auto payload = block::extract_workchain_engine_state(state, 2, td::Bits256::zero()).move_as_ok();
        previous = uno_workchain::UsedNullifiers::from_root(payload, keys.size()).move_as_ok();
      }
      std::vector<td::Bits256> added(64);
      for (auto& key : added) {
        for (auto& byte : key.as_slice()) byte = static_cast<char>(generator() & 255);
      }
      auto next = previous.with_used(added).move_as_ok();
      keys.insert(keys.end(), added.begin(), added.end());
      auto root = single_account_state(next.root());
      database->inc(root);
      retained.push_back(root->get_hash());
      if (retained.size() > 3) {
        database->dec(database->load_cell(retained.front().as_slice()).move_as_ok());
        released.push_back(retained.front());
        retained.erase(retained.begin());
      }
      commit();
    }
    // Drop both the V2 reader and the actual RocksDB handle, not just a cache.
    reopen();
    {
      vm::CellHashSet reachable;
      std::function<void(td::Ref<vm::Cell>)> visit = [&](td::Ref<vm::Cell> cell) {
        if (!reachable.insert(cell).second) return;
        auto slice = vm::load_cell_slice(cell);
        for (unsigned i = 0; i < slice.size_refs(); ++i) visit(slice.prefetch_ref(i));
      };
      for (const auto& hash : retained) visit(database->load_cell(hash.as_slice()).move_as_ok());
      std::size_t stored_cells = 0;
      kv->for_each([&](td::Slice key, td::Slice) {
        if (key.size() == vm::CellTraits::hash_bytes) {
          ASSERT_TRUE(reachable.contains(vm::CellHash::from_slice(key)));
          ++stored_cells;
        }
        return td::Status::OK();
      }).ensure();
      ASSERT_EQ(stored_cells, reachable.size());
      for (const auto& hash : released) ASSERT_TRUE(database->load_cell(hash.as_slice()).is_error());
      auto newest = database->load_cell(retained.back().as_slice()).move_as_ok();
      auto payload = block::extract_workchain_engine_state(newest, 2, td::Bits256::zero()).move_as_ok();
      auto restored = uno_workchain::UsedNullifiers::from_root(payload, keys.size()).move_as_ok();
      for (const auto& key : keys) ASSERT_TRUE(restored.contains(key));
      ASSERT_TRUE(restored.with_used({keys.front()}).is_error());
      LOG(INFO) << "Root retention epoch=" << epoch << " nullifiers=" << keys.size()
                << " roots=" << retained.size() << " live_cells=" << stored_cells;
    }
  }
  for (const auto& hash : retained) database->dec(database->load_cell(hash.as_slice()).move_as_ok());
  commit();
  reopen();
  kv->for_each([&](td::Slice key, td::Slice) {
    ASSERT_TRUE(key.size() != vm::CellTraits::hash_bytes);
    return td::Status::OK();
  }).ensure();
  for (const auto& hash : retained) ASSERT_TRUE(database->load_cell(hash.as_slice()).is_error());
  database.reset();
  kv.reset();
  td::rmrf(directory).ensure();
}

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

TEST(UnoStateSnapshot, HeaderBudgetAndCancellationReleaseImport) {
  auto root = vm::CellBuilder().store_long(0x73506172654d6531, 64)
      .store_ref(vm::CellBuilder().store_long(0x73506172654d6532, 64).finalize()).finalize();
  auto bytes = vm::std_boc_serialize(root).move_as_ok();
  vm::BagOfCells::Info info;
  ASSERT_TRUE(info.parse_serialized_header(bytes.as_slice()) > 0);
  auto bound = tos::validator::streaming_import_encoding_bound(bytes.size(), info.cell_count).move_as_ok();
  td::uint64 too_small;
  ASSERT_TRUE(!__builtin_sub_overflow(bound, td::uint64{1}, &too_small));
  auto saved = tos::validator::fullnode::persistent_state_budget_config();
  auto config = saved;
  config.max_spool_bytes_per_import = too_small;
  tos::validator::fullnode::configure_persistent_state_budgets(config);
  auto file = td::mkstemp("/tmp").move_as_ok();
  file.first.write_all(bytes.as_slice()).ensure();
  file.first.close();
  const auto directory = td::mkdtemp("/tmp", "uno-import-admission-").move_as_ok();
  LOG(WARNING) << "Import admission fixture: " << directory << ", input " << file.second
               << " (removed on success, retained on failure)";
  tos::validator::PersistentStateImportRequest request;
  request.tempfile_path = file.second;
  request.file_size = bytes.size();
  request.expected_root_hash = root->get_hash().bits();
  std::atomic<bool> completed{false};
  {
    td::actor::Scheduler scheduler({2});
    td::actor::ActorOwn<ImportAdmissionActor> actor;
    scheduler.run_in_context([&] {
      actor = td::actor::create_actor<ImportAdmissionActor>("import-admission", directory, request, bound, completed);
    });
    scheduler.run();
  }
  ASSERT_TRUE(completed.load());
  tos::validator::fullnode::configure_persistent_state_budgets(saved);
  td::rmrf(directory).ensure();
  td::unlink(file.second).ensure();
}

TEST(UnoStateSnapshot, V2ActorImportPublishesFreshReader) {
  std::mt19937 generator(73);
  std::vector<td::Bits256> keys(32);
  for (auto& key : keys) {
    for (auto& byte : key.as_slice()) {
      byte = static_cast<char>(generator() & 255);
    }
  }
  auto used = uno_workchain::UsedNullifiers{}.with_used(keys).move_as_ok();
  actor_import_snapshot(single_account_state(used.root()), used.root(), keys, true);
}

TEST(UnoStateSnapshot, TcpSlicesAndTruncatedPeer) {
  // Exercise multiple network responses independently of the small state fixture.
  td::BufferSlice bytes((1u << 21) + 137);
  std::mt19937 generator(43);
  for (auto& byte : bytes.as_slice()) byte = static_cast<char>(generator() & 255);
  auto received = download_uno_snapshot_over_tcp(bytes.clone()).move_as_ok();
  ASSERT_TRUE(received.as_slice() == bytes.as_slice());
  ASSERT_TRUE(download_uno_snapshot_over_tcp(bytes.clone(), true).is_error());
}

TEST(UnoStateSnapshot, TcpFileDownloadOwnership) {
  using namespace tos::validator::fullnode;
  using testing::test_get_persistent_state_download_bytes;
  auto saved_directory = get_persistent_state_tempfile_dir();
  auto directory = td::mkdtemp("/tmp", "uno-snapshot-download-").move_as_ok();
  set_persistent_state_tempfile_dir(directory);
  auto baseline = test_get_persistent_state_download_bytes();
  // Cross the actual production threshold, rather than overriding it in a test.
  const auto size = persistent_state_heap_threshold_bytes() + 137;
  td::BufferSlice source(size);
  std::mt19937 generator(44);
  for (auto& byte : source.as_slice()) byte = static_cast<char>(generator() & 255);
  std::string path;
  {
    auto received = download_uno_snapshot_state_over_tcp(source.clone()).move_as_ok();
    ASSERT_TRUE(received.is_file());
    ASSERT_EQ(received.file().size, size);
    ASSERT_TRUE(received.file().reservation != nullptr);
    ASSERT_EQ(test_get_persistent_state_download_bytes(), baseline + size);
    path = received.file().path;
    ASSERT_TRUE(td::stat(path).is_ok());
    ASSERT_TRUE(path.find(".partial") == std::string::npos);
    auto moved = std::move(received);
    ASSERT_TRUE(td::stat(moved.file().path).is_ok());
    ASSERT_EQ(test_get_persistent_state_download_bytes(), baseline + size);
  }
  ASSERT_TRUE(td::stat(path).is_error());
  ASSERT_EQ(test_get_persistent_state_download_bytes(), baseline);
  ASSERT_TRUE(download_uno_snapshot_state_over_tcp(std::move(source), true).is_error());
  ASSERT_EQ(test_get_persistent_state_download_bytes(), baseline);
  unsigned leftovers = 0;
  td::WalkPath::run(directory, [&](td::CSlice, td::WalkPath::Type type) {
    if (type == td::WalkPath::Type::RegularFile || type == td::WalkPath::Type::Symlink) ++leftovers;
  }).ensure();
  ASSERT_EQ(leftovers, 0u);
  set_persistent_state_tempfile_dir(saved_directory);
}

#ifdef UNO_SNAPSHOT_LARGE_TEST
TEST(UnoStateSnapshot, LargeSingleAccountDownloadAndImport) {
  // Opt-in integration experiment, not a protocol size limit or a benchmark.
  constexpr std::size_t count = 2000000;
  std::mt19937 generator(45);
  std::vector<td::Bits256> keys(count);
  for (auto& key : keys) {
    for (auto& byte : key.as_slice()) byte = static_cast<char>(generator() & 255);
  }
  LOG(WARNING) << "Building large single-account state with " << count << " nullifiers";
  auto used = uno_workchain::UsedNullifiers{}.with_used(keys).move_as_ok();
  auto state = single_account_state(used.root());
  auto bytes = vm::std_boc_serialize(state).move_as_ok();
  LOG(WARNING) << "Large single-account state serialized bytes=" << bytes.size();
  ASSERT_TRUE(bytes.size() > tos::validator::fullnode::persistent_state_heap_threshold_bytes());
  bytes = {};
  LOG(WARNING) << "Large snapshot experiment uses CellDb V2 with 64 MiB cache and 16 MiB parser budget; "
                  "process RSS includes input construction and verification, not just import";
  actor_import_snapshot(state, used.root(), keys, true);
}

#endif

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
