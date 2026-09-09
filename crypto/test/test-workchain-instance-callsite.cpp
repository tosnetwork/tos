#include <iostream>
#include "common/errorlog.h"
#include "validator/impl/validate-query.hpp"
#include "validator/manager-disk.hpp"
#include "td/actor/actor.h"
#include "td/utils/filesystem.h"
#include "td/utils/overloaded.h"
#include "vm/boc.h"

namespace {
using namespace tos;
using namespace tos::validator;
void require(bool ok, int code) {
  if (!ok) { std::cerr << "failure_identity=" << code << '\n'; std::exit(1); }
}
// Only manager statistics callbacks are used. No storage, validation or
// configuration method is overridden or replaced by this sink.
class StatisticsSink final : public ValidatorManagerImpl {
 public:
  StatisticsSink() : ValidatorManagerImpl({}, {}, {}, {}, "", {}, "", "", "") {}
 private:
  void start_up() override {}
};

class ExtraProbe final : public ValidateQuery {
 public:
  ExtraProbe(td::Ref<vm::Cell> root, BlockCandidate candidate, ValidateParams params,
             td::actor::ActorId<ValidatorManager> manager,
             td::Promise<ValidateCandidateResult> result, bool corrupt, bool local_fault)
      : ValidateQuery(std::move(candidate), std::move(params), manager, {}, std::move(result)),
        root_(std::move(root)), corrupt_(corrupt), local_fault_(local_fault) {}
 private:
  td::Ref<vm::Cell> root_;
  bool corrupt_;
  bool local_fault_;
  void start_up() override {
    // This harness seeds the method's authenticated predecessor and candidate
    // context. It runs the production method and its production terminal result
    // handlers; it does not claim full-block validation or consensus acceptance.
    auto config = block::ConfigInfo::extract_config(root_, prev_blocks.at(0), block::ConfigInfo::needStateRoot);
    require(config.is_ok(), 900);
    config_ = config.move_as_ok();
    require(ps_.unpack_state(prev_blocks.at(0), root_).is_ok(), 901);
    require(ns_.unpack_state(prev_blocks.at(0), root_).is_ok(), 902);
    mc_seqno_ = 0;
    now_ = config_->utime;
    is_key_block_ = false;
    create_stats_enabled_ = false;
    prev_key_block_exists_ = true;
    prev_key_block_seqno_ = 0;
    prev_key_block_ = prev_blocks.at(0);
    value_flow_.minted = block::CurrencyCollection{0};
    value_flow_.created = block::CurrencyCollection{0};
    import_created_ = block::CurrencyCollection{0};

    block::gen::McStateExtra::Record next;
    require(tlb::unpack_cell(ps_.mc_state_extra_, next), 903);
    if (local_fault_) {
      // Only the authenticated predecessor slot is malformed. The candidate
      // retains the valid ledger. This measures provenance classification at
      // the method boundary, not authentication of a complete predecessor.
      auto unavailable_predecessor = next;
      unavailable_predecessor.r1.workchain_instances = vm::CellBuilder().finalize();
      require(tlb::pack_cell(ps_.mc_state_extra_, unavailable_predecessor), 915);
    }
    next.r1.after_key_block = false;
    block::gen::ExtBlkRef::Record previous{config_->lt, 0, prev_blocks.at(0).root_hash, prev_blocks.at(0).file_hash};
    vm::CellBuilder last_key;
    last_key.store_long(1, 1);
    require(tlb::pack(last_key, previous), 904);
    next.r1.last_key_block = vm::load_cell_slice_ref(last_key.finalize());
    vm::AugmentedDictionary history(32, block::tlb::aug_OldMcBlocksInfo);
    vm::CellBuilder entry;
    entry.store_long(1, 1);
    require(tlb::pack(entry, previous), 914);
    require(history.set_builder(td::BitArray<32>{0LL}, entry), 905);
    next.r1.prev_blocks = std::move(history).extract_root();
    if (corrupt_) {
      auto parsed = block::read_workchain_instance_ledger(next.r1.workchain_instances);
      require(parsed.is_ok(), 906);
      auto header = parsed.move_as_ok();
      vm::Dictionary entries(header.entries, 32);
      block::gen::WorkchainInstanceRecord::Record injected{1, td::Bits256::ones()};
      vm::CellBuilder value;
      require(tlb::pack(value, injected), 907);
      // Deliberately outside wc=2: the production call must compare the whole
      // ledger even when no wc=3 installation is proposed.
      require(entries.set_builder(td::BitArray<32>{3}, value), 908);
      header.entries = entries.get_root();
      require(tlb::pack_cell(next.r1.workchain_instances, header), 909);
    }
    require(tlb::pack_cell(ns_.mc_state_extra_, next), 910);
    if (check_mc_state_extra()) finish_query();
  }
};
}

int main(int argc, char** argv) {
  require(argc == 4, 920);
  // Production rejection writes diagnostic files before resolving its result.
  // The driver supplies a fresh private directory; diagnostics are not oracles.
  tos::errorlog::ErrorLog::create(argv[3]);
  auto data = td::read_file(td::CSlice(argv[1])); require(data.is_ok(), 921);
  auto decoded = vm::std_boc_deserialize(data.ok().as_slice()); require(decoded.is_ok(), 922);
  auto root = decoded.move_as_ok();
  // The file hash is read from the fixture generator's own output rather than
  // substituted with a root hash. Both files are archived with the fixture.
  auto hash_data = td::read_file(std::string(argv[1]) + ".fhash"); require(hash_data.is_ok(), 923);
  require(hash_data.ok().size() == 32, 924);
  td::Bits256 file_hash; file_hash.as_slice().copy_from(hash_data.ok().as_slice());
  BlockIdExt previous{BlockId{masterchainId, shardIdAll, 0}, root->get_hash().bits(), file_hash};
  BlockCandidate candidate;
  candidate.id = {BlockId{masterchainId, shardIdAll, 1}, td::Bits256::zero(), td::Bits256::zero()};
  candidate.collated_file_hash.set_zero();
  ValidateParams params; params.shard = {masterchainId, shardIdAll}; params.prev = {previous};
  bool corrupt = std::string(argv[2]) == "corrupt";
  bool local_fault = std::string(argv[2]) == "local-fault";
  require(corrupt || local_fault || std::string(argv[2]) == "unchanged", 925);
  int kind = -1;
  td::actor::Scheduler scheduler({0});
  td::actor::ActorOwn<StatisticsSink> sink;
  scheduler.run_in_context([&] {
    sink = td::actor::create_actor<StatisticsSink>("statistics-only");
    auto promise = td::PromiseCreator::lambda([&](td::Result<ValidateCandidateResult> result) {
      if (result.is_error()) {
        kind = 2;
        std::cerr << "local_status=" << result.error().to_string() << '\n';
      } else {
        result.move_as_ok().visit(td::overloaded(
            [&](CandidateAccept) { kind = 0; },
            [&](CandidateReject rejected) { kind = 1; std::cerr << "rejection_diagnostic=" << rejected.reason << '\n'; }));
      }
      // Do not destroy the scheduler while its actor callback is active.
    });
    td::actor::create_actor<ExtraProbe>("mc-extra-probe", root, std::move(candidate), std::move(params),
                                      sink.get(), std::move(promise), corrupt, local_fault).release();
  });
  while (kind == -1 && scheduler.run(1)) {}
  scheduler.run_in_context([&] { sink.reset(); });
  scheduler.stop();
  std::cout << "final_typed_kind=" << kind << '\n';
  require(kind == (local_fault ? 2 : corrupt ? 1 : 0), local_fault ? 932 : corrupt ? 931 : 930);
}
