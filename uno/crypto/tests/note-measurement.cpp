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

// A reachable component history, not proof-bearing or financially authorized
// transactions. Each event consumes two fresh keys and appends two leaves.
TEST(UnoNoteMeasurement, ContinuousComponentHistory) {
  auto tree = NoteTreeState::empty().move_as_ok();
  auto anchors = AnchorWindow::genesis(3,3,tree.root()).move_as_ok();
  const auto owner = td::Bits256::zero();
  auto refund_key = owner;
  refund_key.as_slice()[31] = 101;
  auto second_refund_key = owner;
  second_refund_key.as_slice()[31] = 102;
  const std::vector<td::Bits256> refund_keys{refund_key,second_refund_key};
  auto reserved = NullifierState{}.reserve(owner,refund_keys).move_as_ok();
  auto state = NoteState::assemble(tree,reserved,anchors).move_as_ok();
  std::vector<NoteTreeState::Commitment> all_outputs;
  std::vector<AnchorWindow::Root> expected_roots{tree.root()};
  std::vector<td::Bits256> all_keys;
  for (std::uint64_t height = 1; height <= 5; height = checked_add(height,1)) {
    const auto old_hash = state.to_cell().move_as_ok()->get_hash();
    ASSERT_EQ(state.reserved_leaves(),2u);
    NoteState::SpendEffects collision{state.anchors().latest(),{{refund_key,commitment(101)}}};
    ASSERT_TRUE(state.apply_spend_effects(height,{collision},{1,2,2}).is_error());
    ASSERT_TRUE(state.to_cell().move_as_ok()->get_hash() == old_hash);
    NoteState::SpendEffects event{state.anchors().latest(),{}};
    for (unsigned slot = 0; slot < 2; ++slot) {
      const auto ordinal = checked_add(all_keys.size(),1);
      ASSERT_TRUE(ordinal <= 10);
      auto key = td::Bits256::zero();
      key.as_slice()[31] = static_cast<char>(ordinal); // Checked above before narrowing.
      auto output = commitment(ordinal);
      event.actions.push_back({key,output});
      all_keys.push_back(key);
      all_outputs.push_back(output);
    }
    auto next = state.apply_spend_effects(height,{event},{1,2,2}).move_as_ok();
    // Independent full-prefix reconstruction checks the incremental frontier.
    auto reference = NoteTreeState::empty().move_as_ok()
        .append(all_outputs,0,all_outputs.size()).move_as_ok();
    ASSERT_TRUE(next.tree().root() == reference.root());
    ASSERT_EQ(next.tree().next_position(),all_outputs.size());
    ASSERT_EQ(next.nullifiers().used_count(),all_keys.size());
    ASSERT_TRUE(state.to_cell().move_as_ok()->get_hash() == old_hash);
    ASSERT_TRUE(reference.root() != expected_roots.back());
    expected_roots.push_back(reference.root());
    auto bytes = vm::std_boc_serialize(next.to_cell().move_as_ok()).move_as_ok();
    auto decoded = vm::std_boc_deserialize(bytes.as_slice()).move_as_ok();
    state = NoteState::from_cell(decoded,3,3,{all_keys.size(),2,1,2}).move_as_ok();
    ASSERT_EQ(state.reserved_leaves(),2u);
    for (const auto& key : refund_keys) {
      ASSERT_TRUE(state.nullifiers().try_is_reserved(key).move_as_ok());
      ASSERT_TRUE(!state.nullifiers().try_is_used(key).move_as_ok());
    }
    ASSERT_EQ(state.anchors().height(),height);
    for (std::size_t i = 0; i < expected_roots.size(); i = checked_add(i,1)) {
      // i <= size, so size - i cannot underflow. Three newest roots survive.
      ASSERT_EQ(state.anchors().contains(expected_roots[i]),expected_roots.size() - i <= 3);
    }
    for (const auto& key : all_keys) ASSERT_TRUE(state.nullifiers().try_is_used(key).move_as_ok());
    const auto restored_hash = state.to_cell().move_as_ok()->get_hash();
    event.anchor = state.anchors().latest();
    ASSERT_TRUE(state.apply_spend_effects(checked_add(height,1),{event},{1,2,2}).is_error());
    ASSERT_TRUE(state.to_cell().move_as_ok()->get_hash() == restored_hash);
  }
  // A test driver applies the existing refund primitives, not an authenticated
  // Failed Ack or a new Reserve transition. Five intervening roots have aged.
  const auto pending_hash = state.to_cell().move_as_ok()->get_hash();
  auto settled_nullifiers = state.nullifiers().refund(owner).move_as_ok();
  const std::vector<NoteTreeState::Commitment> refund_outputs{commitment(101),commitment(102)};
  auto settled_tree = state.tree().append(refund_outputs,0,2).move_as_ok();
  auto settled_anchors = state.anchors().finish_block(6,settled_tree.root()).move_as_ok();
  auto settled = NoteState::assemble(settled_tree,settled_nullifiers,settled_anchors).move_as_ok();
  auto settled_bytes = vm::std_boc_serialize(settled.to_cell().move_as_ok()).move_as_ok();
  auto settled_cell = vm::std_boc_deserialize(settled_bytes.as_slice()).move_as_ok();
  auto restored = NoteState::from_cell(settled_cell,3,3,{12,0,1,2}).move_as_ok();
  ASSERT_EQ(restored.tree().next_position(),12u);
  ASSERT_EQ(restored.nullifiers().used_count(),12u);
  ASSERT_EQ(restored.reserved_leaves(),0u);
  ASSERT_EQ(restored.anchors().height(),6u);
  for (const auto& key : refund_keys) {
    ASSERT_TRUE(restored.nullifiers().try_is_used(key).move_as_ok());
    ASSERT_TRUE(!restored.nullifiers().try_is_reserved(key).move_as_ok());
  }
  ASSERT_TRUE(restored.nullifiers().refund(owner).is_error());
  ASSERT_TRUE(state.to_cell().move_as_ok()->get_hash() == pending_hash);
  std::cout << "continuous component history passed: five intervening blocks, reserved-key exclusion, terminal refund\n";
  std::cout.flush();
  ASSERT_TRUE(std::cout.good());
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
