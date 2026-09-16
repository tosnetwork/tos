#pragma once
#include <limits>

#include "vm/excno.hpp"

#include "state.h"
namespace tos::auth {
// What a privileged host charges, in one place.
//
// Two hosts now implement the privileged surface, and each charges for the
// reads it made. Writing the formula twice would be two answers to one
// question: a change to how work is priced would have to be made in both, and
// nothing would notice if it were made in one.
[[noreturn]] inline void refuse_host(const char* reason) {
  throw vm::VmError{vm::Excno::cell_und, reason};
}

// A host that is not the one for this transaction refuses the way the absent
// host does -- the instruction does not exist for this caller.
[[noreturn]] inline void refuse_instruction(const char* reason) {
  throw vm::VmError{vm::Excno::inv_opcode, reason};
}

// The registry reports what each operation read. Charging from that, rather
// than from a constant beside it, keeps the price and the work from drifting
// apart: a change that reads more is charged more without anyone updating a
// second number.
inline std::uint64_t consumed(const StateReadBudget& before, const StateReadBudget& after, std::uint64_t per_entry,
                              std::uint64_t per_byte) {
  auto entries = before.entries >= after.entries ? before.entries - after.entries : 0;
  auto bytes = before.bytes >= after.bytes ? before.bytes - after.bytes : 0;
  // Saturating, because a price that wrapped would be free.
  auto entry_cost = entries > std::numeric_limits<std::uint64_t>::max() / std::max<std::uint64_t>(per_entry, 1)
                        ? std::numeric_limits<std::uint64_t>::max()
                        : entries * per_entry;
  auto byte_cost = bytes > std::numeric_limits<std::uint64_t>::max() / std::max<std::uint64_t>(per_byte, 1)
                       ? std::numeric_limits<std::uint64_t>::max()
                       : bytes * per_byte;
  return entry_cost > std::numeric_limits<std::uint64_t>::max() - byte_cost ? std::numeric_limits<std::uint64_t>::max()
                                                                            : entry_cost + byte_cost;
}

inline long long as_gas(std::uint64_t amount) {
  constexpr auto ceiling = static_cast<std::uint64_t>(std::numeric_limits<long long>::max());
  return static_cast<long long>(amount > ceiling ? ceiling : amount);
}
}  // namespace tos::auth
