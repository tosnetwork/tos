#include "block/block-auto.h"
#include "block/block-parse.h"
#include "vm/excno.hpp"
#include "vm/vmstate.h"

#include "cells.h"
#include "codec.h"
#include "native-config-host.h"
#include "native-election-binding.h"
namespace tos::auth {
namespace {
[[noreturn]] void refuse(const char* reason) {
  throw vm::VmError{vm::Excno::cell_und, reason};
}

// The registry reports what each operation read. Charging from that, rather
// than from a constant beside it, keeps the price and the work from drifting
// apart: a change that reads more is charged more without anyone updating a
// second number.
std::uint64_t consumed(const StateReadBudget& before, const StateReadBudget& after, std::uint64_t per_entry,
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

long long as_gas(std::uint64_t amount) {
  constexpr auto ceiling = static_cast<std::uint64_t>(std::numeric_limits<long long>::max());
  return static_cast<long long>(amount > ceiling ? ceiling : amount);
}
}  // namespace

td::Ref<vm::Cell> NativeConfigHost::checkpoint(const Charge& charge) {
  auto before = accepted_.state().remaining();
  auto encoded = accepted_.state().checkpoint();
  if (!encoded.ok())
    refuse("native registry checkpoint");
  auto after = accepted_.state().remaining();
  charge(as_gas(consumed(before, after, gas_per_entry_, gas_per_byte_)));
  ++checkpoints_;
  return encoded.value();
}

td::Ref<vm::Cell> NativeConfigHost::apply(td::Ref<vm::Cell> update, td::Ref<vm::Cell> evidence, const Charge& charge) {
  if (update.is_null() || evidence.is_null())
    refuse("native update operand");

  auto raw_update = unpack_bytes(std::move(update));
  if (!raw_update.ok())
    refuse("native update encoding");
  auto raw_evidence = unpack_bytes(std::move(evidence));
  if (!raw_evidence.ok())
    refuse("native evidence encoding");

  auto decoded_update = decode<Update>(raw_update.value());
  if (!decoded_update.ok())
    refuse("native update");
  auto decoded_evidence = decode<Authorizations>(raw_evidence.value());
  if (!decoded_evidence.ok())
    refuse("native evidence");

  auto before = accepted_.state().remaining();
  // Applied against the accepted prefix, never against a prefix a failed
  // transaction left behind.
  auto next = accepted_.apply_transaction(decoded_update.value(), decoded_evidence.value(), context_, reader_);
  if (!next.ok())
    refuse("native update refused");

  auto encoded = next.value().state().checkpoint();
  if (!encoded.ok())
    refuse("native registry checkpoint");

  auto after = next.value().state().remaining();
  charge(as_gas(consumed(before, after, gas_per_entry_, gas_per_byte_)));
  // Staged only after every step succeeded, so a refusal above cannot have
  // advanced the prefix.
  accepted_ = std::move(next.value());
  ++updates_;
  return encoded.value();
}

td::Ref<vm::Cell> NativeConfigHost::bind(td::Ref<vm::Cell> elected, td::Ref<vm::Cell> bindings, const Charge& charge) {
  if (elected.is_null() || bindings.is_null())
    refuse("native binding operand");

  // The registry the binding is read from is the one this transaction has
  // accepted so far, not the one the block started with: an update applied
  // earlier in this same transaction is part of what the set is bound against.
  auto before = accepted_.state().remaining();
  auto checkpoint = accepted_.state().checkpoint();
  if (!checkpoint.ok())
    refuse("native registry checkpoint");
  auto registry = RegistryView::open(checkpoint.value(), coordinate_, accepted_.state().remaining());
  if (!registry.ok())
    refuse("native registry unreadable");

  block::gen::ValidatorSet::Record_validators_ext set;
  if (!tlb::unpack_cell(elected, set))
    refuse("native binding set");
  auto declared = decode_elected_bindings(std::move(bindings), set.total);
  if (!declared.ok())
    refuse("native binding encoding");

  auto bound = bind_elected_validators(std::move(elected), declared.value(), registry.value(), coordinate_);
  if (!bound.ok())
    refuse("native binding refused");

  auto after = accepted_.state().remaining();
  charge(as_gas(consumed(before, after, gas_per_entry_, gas_per_byte_)));
  ++bindings_;
  return bound.value();
}
}  // namespace tos::auth
