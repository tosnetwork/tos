#include <random>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/workchain-block-execution.h"
#include "td/utils/port/path.h"
#include "td/utils/tests.h"
#include "uno/core/used-nullifiers.h"
#include "validator/downloaders/download-state.hpp"
#include "validator/state-serializer.hpp"
#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"

namespace {
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
