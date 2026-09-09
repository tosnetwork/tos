// Test-only, one-bit adaptive directory. No account addresses, wire schema,
// authenticated proofs, coordinator encoding or production admission policy.
#include "uno/core/used-nullifiers.h"
#include "vm/boc.h"
#include <algorithm>
#include <chrono>
#include <iostream>
#include <limits>
#include <random>
#include <set>
#include <stdexcept>
#include <string>
#include <sys/resource.h>

namespace {
using Key = td::Bits256;
using Used = uno_workchain::UsedNullifiers;
void require(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
std::uint64_t add(std::uint64_t a, std::uint64_t b) {
  require(b <= UINT64_MAX - a,"counter overflow");
  return a + b;
}
template <class T> T take(td::Result<T> result) {
  if (result.is_error()) throw std::runtime_error(result.move_as_error().to_string());
  return result.move_as_ok();
}
unsigned bit(const Key& key, unsigned depth) {
  require(depth < 256,"key depth exhausted");
  // depth % 8 is at most 7, so the subtraction cannot underflow.
  return (static_cast<unsigned char>(key.as_slice()[depth / 8]) >> (7 - depth % 8)) & 1u;
}
struct Node {
  unsigned depth = 0;
  std::size_t left = SIZE_MAX, right = SIZE_MAX;
  std::vector<Key> keys;
  Used used;
  std::uint64_t cells = 0;
  bool leaf() const { return left == SIZE_MAX; }
};
struct Directory {
  std::vector<Node> nodes;
  std::size_t locate(const Key& key) const {
    std::size_t index = 0;
    while (!nodes[index].leaf()) {
      const auto& node = nodes[index];
      index = bit(key,node.depth) ? node.right : node.left;
      require(index < nodes.size(),"directory child out of range");
    }
    return index;
  }
  bool accepts_claim(const Key& key, std::size_t claimed) const { return locate(key) == claimed; }
  bool contains(const Key& key) const { return take(nodes[locate(key)].used.try_contains(key)); }
};
Node leaf(std::vector<Key> keys, unsigned depth, const Used* cached = nullptr, std::uint64_t cached_cells = 0) {
  Node node;
  node.depth = depth;
  node.keys = std::move(keys);
  node.used = cached ? *cached : take(Used{}.with_used(node.keys));
  if (cached) {
    node.cells = cached_cells;
  } else if (node.used.root().not_null()) {
    vm::CellStorageStat stat;
    (void)take(stat.compute_used_storage(node.used.root()));
    node.cells = stat.cells;
  }
  return node;
}
Directory build(const std::vector<Key>& keys, std::uint64_t cell_limit, std::uint64_t node_limit) {
  require(cell_limit > 0 && node_limit > 0 && node_limit <= 1048575,"invalid experiment budget");
  Directory result;
  result.nodes.push_back(leaf(keys,0));
  for (std::size_t i = 0; i < result.nodes.size(); i = add(i,1)) {
    if (result.nodes[i].cells <= cell_limit) continue;
    const auto depth = result.nodes[i].depth;
    require(depth < 256,"unsplittable leaf exceeds Cell control");
    // Short-circuit establishes node_limit >= 2 before subtracting.
    require(node_limit >= 2 && result.nodes.size() <= node_limit - 2,"directory node budget exceeded");
    auto source = std::move(result.nodes[i].keys);
    auto cached = result.nodes[i].used;
    const auto cached_cells = result.nodes[i].cells;
    std::vector<Key> children[2];
    for (const auto& key : source) children[bit(key,depth)].push_back(key);
    result.nodes[i].left = result.nodes.size();
    result.nodes[i].right = add(result.nodes.size(),1);
    result.nodes[i].used = {};
    result.nodes[i].cells = 0;
    for (auto& child : children) {
      const bool unchanged = child.size() == source.size();
      // An unchanged key group reuses the identical immutable root and its
      // measured size, not a guess based on descendant residency.
      // depth < 256 was checked above; its checked successor fits unsigned.
      const auto child_depth = static_cast<unsigned>(add(depth,1));
      result.nodes.push_back(leaf(std::move(child),child_depth,unchanged ? &cached : nullptr,cached_cells));
    }
  }
  return result;
}
void validate(const Directory& directory, const std::vector<Key>& keys, std::uint64_t cell_limit) {
  std::uint64_t total = 0;
  for (std::size_t i = 0; i < directory.nodes.size(); i = add(i,1)) {
    const auto& node = directory.nodes[i];
    if (node.leaf()) {
      vm::CellStorageStat stat;
      if (node.used.root().not_null()) (void)take(stat.compute_used_storage(node.used.root()));
      require(stat.cells == node.cells,"cached leaf size differs from actual closure");
      require(node.cells <= cell_limit,"oversized final leaf");
      require(node.used.size() == node.keys.size(),"leaf key count mismatch");
      total = add(total,node.keys.size());
      for (const auto& key : node.keys) require(directory.locate(key) == i,"key stored under wrong prefix");
    } else {
      require(node.used.root().is_null() && node.keys.empty(),"directory retained page payload");
      require(node.left < directory.nodes.size() && node.right < directory.nodes.size(),"missing directory child");
      require(directory.nodes[node.left].depth == add(node.depth,1) &&
              directory.nodes[node.right].depth == add(node.depth,1),"nonconsecutive prefix depth");
    }
  }
  require(total == keys.size(),"directory lost keys");
  for (const auto& key : keys) require(directory.contains(key),"source key missing after split");
}
void self_test() {
  auto first = Key::zero(), second = first, absent = first;
  second.as_slice()[31] = 1;
  absent.as_slice()[0] = static_cast<char>(128);
  const std::vector<Key> keys{first,second};
  auto directory = build(keys,1,513);
  validate(directory,keys,1);
  require(directory.nodes.size() == 513,"last-bit split directory shape changed");
  require(directory.nodes[directory.locate(first)].depth == 256,"last-bit split not reached");
  require(directory.locate(first) != directory.locate(second),"distinct keys share oversized leaf");
  require(!directory.contains(absent) && directory.nodes[directory.locate(absent)].depth == 1,
          "empty key range has no canonical owner");
  require(directory.accepts_claim(absent,directory.locate(absent)),"canonical absent-key claim rejected");
  require(!directory.accepts_claim(first,directory.locate(second)),"wrong claimed page accepted");
  bool exhausted = false, duplicate = false, overflow = false;
  try { (void)build(keys,1,512); } catch (const std::runtime_error&) { exhausted = true; }
  try { (void)build({first,first},1,513); } catch (const std::runtime_error&) { duplicate = true; }
  try { (void)add(UINT64_MAX,1); } catch (const std::runtime_error&) { overflow = true; }
  require(exhausted && duplicate && overflow,"budget, duplicate or arithmetic check ineffective");
  validate(directory,keys,1);
  std::cout << "self-test passed: last-bit split, empty ranges, claims, budgets, duplicate, checked counters\n";
}
std::uint64_t number(const char* s) {
  require(*s != 0,"empty number");
  std::uint64_t n = 0;
  for (; *s; ++s) {
    require(*s >= '0' && *s <= '9' && n <= UINT64_MAX / 10,"invalid number");
    n = add(n * 10,static_cast<unsigned>(*s - '0'));
  }
  return n;
}
void measure(int argc, char** argv) {
  require(argc == 6,"usage: measure-adaptive-partition entries prefix_bits leaf_cells directory_nodes seed");
  const auto count = number(argv[1]), prefix = number(argv[2]), cells = number(argv[3]);
  const auto node_limit = number(argv[4]), seed = number(argv[5]);
  require(count <= 65536 && (prefix == 0 || prefix == 128),"unsupported experiment dimensions");
  std::mt19937_64 random(seed);
  std::vector<Key> keys;
  std::set<Key> seen;
  std::uint64_t attempts = 0;
  while (keys.size() < count) {
    attempts = add(attempts,1);
    require(attempts <= add(add(count,count),16),"key generation did not make bounded progress");
    auto key = Key::zero();
    for (auto& byte : key.as_slice()) byte = static_cast<char>(random() & 255);
    if (prefix == 128) for (unsigned i = 0; i < 16; ++i) key.as_slice()[i] = 0;
    if (seen.insert(key).second) keys.push_back(key);
  }
  const auto started = std::chrono::steady_clock::now();
  auto directory = build(keys,cells,node_limit);
  const auto milliseconds = std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-started).count();
  validate(directory,keys,cells);
  std::uint64_t leaves = 0, empty = 0, maximum = 0;
  unsigned depth = 0;
  for (const auto& node : directory.nodes) if (node.leaf()) {
    leaves = add(leaves,1);
    if (node.keys.empty()) empty = add(empty,1);
    maximum = std::max(maximum,node.cells);
    depth = std::max(depth,node.depth);
  }
  rusage usage{};
  require(getrusage(RUSAGE_SELF,&usage) == 0 && usage.ru_maxrss > 0,"RSS unavailable");
  std::cout << "ADAPTIVE_CSV," << count << ',' << prefix << ',' << cells << ',' << node_limit << ',' << seed << ','
            << directory.nodes.size() << ',' << leaves << ',' << empty << ',' << depth << ',' << maximum << ','
            << milliseconds << ',' << usage.ru_maxrss << '\n';
}
}
int main(int argc, char** argv) {
  try {
    if (argc == 2 && std::string(argv[1]) == "--self-test") self_test(); else measure(argc,argv);
    std::cout.flush();
    require(std::cout.good(),"measurement output failed");
    return 0;
  } catch (const std::exception& e) { std::cerr << "measurement failed: " << e.what() << '\n'; }
    catch (vm::VmError&) { std::cerr << "measurement failed: VM Cell error\n"; }
    catch (vm::VmVirtError&) { std::cerr << "measurement failed: virtualized Cell\n"; }
    catch (vm::VmNoGas&) { std::cerr << "measurement failed: VM budget\n"; }
    catch (vm::CellBuilder::CellCreateError&) { std::cerr << "measurement failed: Cell construction\n"; }
    catch (vm::CellBuilder::CellWriteError&) { std::cerr << "measurement failed: Cell capacity\n"; }
  return 1;
}
