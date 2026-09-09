#pragma once

#include <cstdint>
#include <vector>
#include "td/utils/Status.h"
#include "vm/dict.h"

namespace block::test {

// Test data for Native storage/import experiments: a plain 256-bit dictionary
// with empty values. No asset, spend, ownership or production state semantics.
// Native decoding exceptions deliberately fail the test at its outer boundary.
class FixtureDictionary {
 public:
  FixtureDictionary() = default;

  static td::Result<FixtureDictionary> from_root(td::Ref<vm::Cell> root, std::uint64_t max_entries) {
    vm::Dictionary dictionary(root, 256);
    std::uint64_t remaining = max_entries;
    if (!dictionary.check_for_each([&](td::Ref<vm::CellSlice> value, td::ConstBitPtr, int width) {
          if (width != 256 || remaining == 0 || !value->empty_ext()) return false;
          --remaining;  // Positive remainder checked before consuming this entry.
          return true;
        })) return td::Status::Error("invalid fixture dictionary or excessive entries");
    // remaining starts at max_entries and only decreases after a positive check.
    return FixtureDictionary(std::move(root), max_entries - remaining);
  }

  td::Ref<vm::Cell> root() const { return root_; }
  std::uint64_t size() const { return size_; }
  bool contains(const td::Bits256& key) const {
    return vm::Dictionary(root_, 256).lookup(key).not_null();
  }
  td::Result<FixtureDictionary> with_entries(const std::vector<td::Bits256>& keys) const {
    if (keys.size() > UINT64_MAX - size_) return td::Status::Error("fixture entry count overflow");
    vm::Dictionary next(root_, 256);
    vm::CellBuilder empty;
    for (const auto& key : keys) {
      if (!next.set_builder(key, empty, vm::Dictionary::SetMode::Add)) {
        return td::Status::Error("duplicate fixture key");
      }
    }
    // The checked remainder above bounds this addition; failures never publish next.
    return FixtureDictionary(std::move(next).extract_root_cell(), size_ + keys.size());
  }

 private:
  FixtureDictionary(td::Ref<vm::Cell> root, std::uint64_t size) : root_(std::move(root)), size_(size) {}
  td::Ref<vm::Cell> root_;
  std::uint64_t size_ = 0;
};

}  // namespace block::test
