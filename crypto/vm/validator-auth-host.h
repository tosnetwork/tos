#pragma once
#include <functional>
#include <memory>

#include "common/refcnt.hpp"
#include "vm/cells.h"
namespace vm {
// Injected only by native transaction execution. Neither SETC7 nor nested RUNVM
// constructs this authority. Implementations stage effects until native commit.
class ValidatorAuthHost {
 public:
  using Charge = std::function<void(long long)>;
  virtual ~ValidatorAuthHost() = default;
  virtual td::Ref<Cell> checkpoint(const Charge&) = 0;
  virtual td::Ref<Cell> apply(td::Ref<Cell> update, td::Ref<Cell> evidence, const Charge&) = 0;
  // Attaches each elected member's registry binding, or refuses the whole set.
  // The contract asks rather than deciding: the registry is parsed here and
  // nowhere else, so a contract-side derivation would be a second reading of it.
  virtual td::Ref<Cell> bind(td::Ref<Cell> elected, td::Ref<Cell> bindings, const Charge&) = 0;
};
}  // namespace vm
