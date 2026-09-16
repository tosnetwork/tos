#pragma once
#include <cstdint>
#include <functional>
#include <memory>

#include "common/refcnt.hpp"
#include "vm/cells.h"
namespace vm {
// What a privileged instruction lets a host spend.
//
// Two kinds of work, priced from two different places. Gas is what the host
// reports having done, at a price the host carries. A signature verification is
// priced by the machine, at the tariff it already publishes for that primitive,
// so the host never carries a second copy of a price and the two cannot drift.
//
// A verification is reported before it is performed, not counted after. A host
// that checked four hundred signatures and only then discovered the transaction
// could not pay would have done the work anyway, which is the whole of the
// attack; reporting first is what lets the charge stop the next one.
struct HostCharge {
  std::function<void(long long)> gas;
  std::function<void(std::uint16_t suite)> signature_check;
};
// Injected only by native transaction execution. Neither SETC7 nor nested RUNVM
// constructs this authority. Implementations stage effects until native commit.
class ValidatorAuthHost {
 public:
  using Charge = HostCharge;
  virtual ~ValidatorAuthHost() = default;
  virtual td::Ref<Cell> checkpoint(const Charge&) = 0;
  virtual td::Ref<Cell> apply(td::Ref<Cell> update, td::Ref<Cell> evidence, const Charge&) = 0;
  // Attaches each elected member's registry binding, or refuses the whole set.
  // The contract asks rather than deciding: the registry is parsed here and
  // nowhere else, so a contract-side derivation would be a second reading of it.
  virtual td::Ref<Cell> bind(td::Ref<Cell> elected, td::Ref<Cell> bindings, const Charge&) = 0;
};
}  // namespace vm
