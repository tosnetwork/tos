// Existing state components only: no proof-bearing transaction or Reserve.
#include "uno/core/private-transfer-state.h"
#include "td/utils/tests.h"
#include "vm/boc.h"
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <random>
#include <set>
#include <string>
#include <sys/resource.h>

namespace {
using namespace uno_workchain;
using Clock = std::chrono::steady_clock;
bool try_add(std::uint64_t a, std::uint64_t b, std::uint64_t& result) {
  if (b > std::numeric_limits<std::uint64_t>::max() - a) return false;
  result = a + b;
  return true;
}
std::uint64_t checked_add(std::uint64_t a, std::uint64_t b) {
  std::uint64_t result = 0;
  ASSERT_TRUE(try_add(a,b,result));
  return result;
}
double elapsed_ms(Clock::time_point start) {
  return std::chrono::duration<double,std::milli>(Clock::now() - start).count();
}
NoteTreeState::Commitment commitment(std::uint64_t n) {
  NoteTreeState::Commitment result{};
  for (unsigned i = 0; i < 8; ++i) result[i] = static_cast<td::uint8>(n >> (i * 8));
  return result;
}
}

TEST(UnoNoteMeasurement, ExistingComponentEnvelope) {
  std::uint64_t untouched = 7;
  ASSERT_TRUE(!try_add(UINT64_MAX,1,untouched));
  ASSERT_EQ(untouched,7u);
  const char* count_text = std::getenv("TOS_UNO_NOTE_KEYS");
  const char* window_text = std::getenv("TOS_UNO_NOTE_WINDOW");
  const char* profile_text = std::getenv("TOS_UNO_NOTE_HISTORY");
  ASSERT_TRUE(count_text && window_text && profile_text);
  const std::string count_value(count_text), window_value(window_text), profile(profile_text);
  std::uint64_t count = UINT64_MAX;
  for (auto value : {0u,8u,1024u,8192u,13080u,13100u,13105u,13106u,65536u})
    if (count_value == std::to_string(value)) count = value;
  const std::uint32_t window = window_value == "3" ? 3 : window_value == "100" ? 100 : 0;
  ASSERT_TRUE(count != UINT64_MAX && window && (profile == "spent" || profile == "owners"));
  const auto total = checked_add(count,2);
  std::mt19937_64 random(45);
  std::set<td::Bits256> seen;
  std::vector<td::Bits256> keys;
  while (keys.size() < total) {
    auto key = td::Bits256::zero();
    for (auto& byte : key.as_slice()) byte = static_cast<char>(random() & 255);
    ASSERT_TRUE(key != td::Bits256::zero());
    if (seen.insert(key).second) keys.push_back(key);
  }
  std::vector<NoteTreeState::Commitment> commitments;
  for (std::uint64_t i = 0; i < count; i = checked_add(i,1)) commitments.push_back(commitment(i));
  auto tree = NoteTreeState::empty().move_as_ok().append(commitments,0,count).move_as_ok();
  NullifierState nullifiers;
  for (std::uint64_t i = 0; i < count; i = checked_add(i,1)) {
    nullifiers = profile == "owners" ?
        nullifiers.reserve(keys[i],{keys[i]}).move_as_ok().refund(keys[i]).move_as_ok() :
        nullifiers.with_used({keys[i]}).move_as_ok();
  }
  auto anchors = AnchorWindow::genesis(window,window,tree.root()).move_as_ok();
  for (std::uint64_t height = 1; height < window; height = checked_add(height,1))
    anchors = anchors.finish_block(height,tree.root()).move_as_ok();
  const auto owner = td::Bits256::zero();
  const std::vector<td::Bits256> fresh{keys[count],keys[checked_add(count,1)]};
  auto pending_nullifiers = nullifiers.reserve(owner,fresh).move_as_ok();
  auto pending = NoteState::assemble(tree,pending_nullifiers,anchors).move_as_ok();
  const auto pending_hash = pending.to_cell().move_as_ok()->get_hash();
  ASSERT_EQ(pending.reserved_leaves(),2u);
  const auto transition_started = Clock::now();
  auto refunded_nullifiers = pending_nullifiers.refund(owner).move_as_ok();
  auto refunded_tree = tree.append({commitment(count),commitment(checked_add(count,1))},0,2).move_as_ok();
  auto refunded_anchors = anchors.finish_block(checked_add(anchors.height(),1),refunded_tree.root()).move_as_ok();
  auto refunded = NoteState::assemble(refunded_tree,refunded_nullifiers,refunded_anchors).move_as_ok();
  const auto transition_ms = elapsed_ms(transition_started);
  ASSERT_EQ(refunded.reserved_leaves(),0u);
  ASSERT_TRUE(pending.to_cell().move_as_ok()->get_hash() == pending_hash);
  for (bool terminal : {false,true}) {
    const auto& notes = terminal ? refunded : pending;
    auto state = PrivateTransferState::assemble(notes,{}).move_as_ok();
    auto start = Clock::now();
    auto cell = state.to_cell().move_as_ok();
    const auto encode_ms = elapsed_ms(start);
    start = Clock::now();
    auto bytes = vm::std_boc_serialize(cell).move_as_ok();
    const auto serialize_ms = elapsed_ms(start);
    start = Clock::now();
    auto root = vm::std_boc_deserialize(bytes.as_slice()).move_as_ok();
    const auto owners = profile == "owners" ? checked_add(count,1) : 1;
    const auto manifests = profile == "owners" ? total : 2;
    auto restored = PrivateTransferState::from_cell(root,window,window,{total,2,owners,manifests}).move_as_ok();
    const auto restore_ms = elapsed_ms(start);
    ASSERT_TRUE(restored.to_cell().move_as_ok()->get_hash() == cell->get_hash());
    ASSERT_EQ(restored.notes().tree().next_position(),terminal ? total : count);
    ASSERT_EQ(restored.notes().reserved_leaves(),terminal ? 0u : 2u);
    ASSERT_EQ(restored.notes().anchors().size(),window);
    for (std::uint64_t i = 0; i < count; i = checked_add(i,1)) {
      ASSERT_TRUE(restored.notes().nullifiers().try_is_used(keys[i]).move_as_ok());
      if (profile == "owners") {
        vm::Dictionary owners_dict(restored.notes().nullifiers().owners_root(),256);
        auto record = owners_dict.lookup(keys[i]);
        ASSERT_TRUE(record.not_null() && record->prefetch_ulong(2) == 2);
      }
    }
    for (const auto& key : fresh) {
      ASSERT_EQ(restored.notes().nullifiers().try_is_used(key).move_as_ok(),terminal);
      ASSERT_EQ(restored.notes().nullifiers().try_is_reserved(key).move_as_ok(),!terminal);
    }
    vm::CellStorageStat stats;
    stats.compute_used_storage(cell).ensure();
    rusage usage{};
    ASSERT_TRUE(getrusage(RUSAGE_SELF,&usage) == 0 && usage.ru_maxrss > 0);
    std::cout << "NOTE_COMPONENT_CSV," << count << ",45," << window << ',' << profile << ','
              << (terminal ? "refunded" : "pending") << ',' << stats.cells << ',' << stats.bits << ','
              << cell->get_depth() << ',' << bytes.size() << ',' << (stats.cells <= 65536) << ','
              << transition_ms << ',' << encode_ms << ',' << serialize_ms << ',' << restore_ms << ','
              << usage.ru_maxrss << std::endl;
    ASSERT_TRUE(std::cout.good());
  }
}
