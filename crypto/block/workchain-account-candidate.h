#pragma once

#include <utility>
#include "vm/cells/Cell.h"

namespace block {

// Transport only, not an admission result or a new wire envelope. The caller
// explicitly supplies both untrusted roots; absent roots are preserved rather
// than replaced with canonical empty objects. Each consumer applies its own
// admission, interpretation and independent reconstruction to these bytes.
// Do not add derived identity/count/coverage/verdict fields to this carrier.
class WorkchainAccountCandidate final {
 public:
  WorkchainAccountCandidate(td::Ref<vm::Cell> candidate, td::Ref<vm::Cell> declarations)
      : candidate_(std::move(candidate)), declarations_(std::move(declarations)) {}

  const td::Ref<vm::Cell>& candidate() const { return candidate_; }
  const td::Ref<vm::Cell>& declarations() const { return declarations_; }

 private:
  td::Ref<vm::Cell> candidate_;
  td::Ref<vm::Cell> declarations_;
};

}  // namespace block
