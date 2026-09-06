#include <chrono>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <sys/resource.h>

#include "block/workchain-input-admission.h"
#include "uno/core/anchor-window.h"

namespace {
using Clock = std::chrono::steady_clock;
std::uint64_t add(std::uint64_t a, std::uint64_t b) {
  if (b > std::numeric_limits<std::uint64_t>::max() - a) throw std::runtime_error("counter overflow");
  return a + b;
}
std::uint64_t multiply(std::uint64_t a, std::uint64_t b) {
  if (a && b > std::numeric_limits<std::uint64_t>::max() / a) throw std::runtime_error("counter overflow");
  return a * b;
}
std::uint64_t subtract(std::uint64_t a, std::uint64_t b) {
  if (b > a) throw std::runtime_error("counter underflow");
  return a - b;
}
void require(bool value) {
  if (!value) throw std::runtime_error("measurement property failed");
}
td::Ref<vm::Cell> graph(std::uint64_t leaves) {
  std::vector<td::Ref<vm::Cell>> level;
  for (std::uint64_t i = 0; i < leaves; i = add(i, 1)) {
    vm::CellBuilder cell;
    cell.store_long(i, 64);
    cell.store_long(91, 64);
    cell.store_long(0, 64);
    cell.store_long(0, 64);
    level.push_back(cell.finalize());
  }
  while (level.size() > 1) {
    require(level.size() % 2 == 0);
    std::vector<td::Ref<vm::Cell>> next;
    for (std::size_t i = 0; i < level.size(); i = add(i, 2)) {
      next.push_back(vm::CellBuilder().store_ref(level[i]).store_ref(level[add(i, 1)]).finalize());
    }
    level = std::move(next);
  }
  require(!level.empty());
  return level.front();
}
block::ResolvedInputPolicy policy(block::WorkchainInputLimits limits) {
  auto result = block::ResolvedInputPolicy::from_resolved_fields(
      limits, block::InputPolicyIdentity{vm::CellHash{}, 1, 91, 1, 1});
  require(std::holds_alternative<block::ResolvedInputPolicy>(result));
  return std::get<block::ResolvedInputPolicy>(result);
}
double elapsed(Clock::time_point start) {
  return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}
template <class T> T take(td::Result<T> result) {
  if (result.is_error()) throw std::runtime_error(result.move_as_error().to_string());
  return result.move_as_ok();
}
uno_workchain::AnchorWindow::Root anchor_root(std::uint64_t height) {
  uno_workchain::AnchorWindow::Root root{};
  for (unsigned i = 0; i < 8; ++i) root[i] = static_cast<std::uint8_t>(height >> multiply(i, 8));
  return root;
}
void anchor_self_test() {
  auto anchors = take(uno_workchain::AnchorWindow::genesis(2, 2, anchor_root(0)));
  anchors = take(anchors.finish_block(1, anchor_root(1)));
  anchors = take(anchors.finish_block(2, anchor_root(2)));
  require(anchors.size() == 2 && !anchors.contains(anchor_root(0)) && anchors.contains(anchor_root(1)));
  auto encoded = take(anchors.to_cell());
  auto restored = take(uno_workchain::AnchorWindow::from_cell(encoded, 2, 2));
  require(restored.height() == 2 && restored.latest() == anchor_root(2));
  std::cout << "{\"anchor_self_test\":\"passed\"}\n";
}
void measure_anchors() {
  auto anchors = take(uno_workchain::AnchorWindow::genesis(100, 100, anchor_root(0)));
  for (std::uint64_t height = 1; height <= 1200; height = add(height, 1)) {
    auto start = Clock::now();
    anchors = take(anchors.finish_block(height, anchor_root(height)));
    const auto finish_ms = elapsed(start);
    start = Clock::now();
    auto encoded = take(anchors.to_cell());
    const auto encode_ms = elapsed(start);
    start = Clock::now();
    auto restored = take(uno_workchain::AnchorWindow::from_cell(encoded, 100, 100));
    const auto decode_ms = elapsed(start);
    require(restored.height() == height && restored.latest() == anchor_root(height));
    require(restored.size() <= 100);
    if (height >= 100) require(!restored.contains(anchor_root(subtract(height, 100))));
    rusage usage{};
    require(getrusage(RUSAGE_SELF, &usage) == 0);
    std::cout << "{\"height\":" << height << ",\"window_size\":" << restored.size()
              << ",\"finish_ms\":" << finish_ms << ",\"encode_ms\":" << encode_ms
              << ",\"decode_ms\":" << decode_ms << ",\"depth\":" << encoded->get_depth()
              << ",\"process_hwm_kib\":" << usage.ru_maxrss << "}\n";
  }
}
void self_test() {
  auto root = graph(2);
  block::CandidateAdmissionSession exact(root, policy({3, 512, 1}));
  const auto& result = exact.evaluate();
  require(std::holds_alternative<block::AdmittedInput>(result));
  const auto& admitted = std::get<block::AdmittedInput>(result);
  require(admitted.usage().cells == 3 && admitted.usage().bits == 512 && admitted.usage().roots == 1);
  require(admitted.candidate()->get_hash() == root->get_hash());
  block::CandidateAdmissionSession over(root, policy({2, 512, 1}));
  std::uint64_t downstream_calls = 0;
  if (std::holds_alternative<block::AdmittedInput>(over.evaluate())) downstream_calls = add(downstream_calls, 1);
  require(downstream_calls == 0);
  require(std::holds_alternative<block::CandidateInvalid>(over.evaluate()));
  require(std::get<block::CandidateInvalid>(over.evaluate()).code == block::CandidateInvalidCode::CellLimit);
  bool overflow = false;
  try { (void)add(UINT64_MAX, 1); } catch (const std::runtime_error&) { overflow = true; }
  require(overflow);
  std::cout << "{\"self_test\":\"passed\",\"over_limit_downstream_calls\":0}\n";
}
void measure(std::uint64_t leaves) {
  require(leaves && (leaves & subtract(leaves, 1)) == 0 && leaves <= 32768);
  const auto cells = subtract(multiply(leaves, 2), 1);
  const auto bits = multiply(leaves, 256);
  auto root = graph(leaves);
  for (std::uint64_t sample = 0; sample < 20; sample = add(sample, 1)) {
    auto start = Clock::now();
    block::WorkchainInputPreflight low({cells, bits, 1});
    require(low.add(root).is_ok());
    const auto walk_ms = elapsed(start);
    start = Clock::now();
    block::CandidateAdmissionSession session(root, policy({cells, bits, 1}));
    const auto& result = session.evaluate();
    require(std::holds_alternative<block::AdmittedInput>(result));
    const auto admission_ms = elapsed(start);
    const auto& admitted = std::get<block::AdmittedInput>(result);
    require(admitted.usage().cells == cells && admitted.usage().bits == bits);
    require(admitted.candidate()->get_hash() == root->get_hash());
    rusage usage{};
    require(getrusage(RUSAGE_SELF, &usage) == 0);
    std::cout << "{\"leaves\":" << leaves << ",\"cells\":" << cells << ",\"bits\":" << bits
              << ",\"roots\":1,\"sample\":" << sample << ",\"walk_ms\":" << walk_ms
              << ",\"detached_admission_ms\":" << admission_ms << ",\"process_hwm_kib\":" << usage.ru_maxrss
              << "}\n";
  }
}
}  // namespace
int main(int argc, char** argv) try {
  if (argc == 2 && std::string(argv[1]) == "--self-test") self_test();
  else if (argc == 2 && std::string(argv[1]) == "--anchor-self-test") anchor_self_test();
  else if (argc == 2 && std::string(argv[1]) == "--anchors") measure_anchors();
  else if (argc == 2) measure(std::stoull(argv[1]));
  else throw std::runtime_error("usage: measure-input-admission --self-test|power-of-two-leaves");
  return 0;
} catch (...) {
  std::cerr << "input admission measurement failed\n";
  return 1;
}
