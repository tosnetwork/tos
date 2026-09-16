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
  // The operand must be the evidence this transaction was admitted with. It is
  // the same reference the contract received, so recognising it is the whole
  // check; decoding it again would make the instruction a second authority on
  // what the transaction carried, reading a container as though it were the
  // authorizations inside it.
  if (admitted_evidence_.is_null() || evidence->get_hash() != admitted_evidence_->get_hash())
    refuse("native evidence operand");

  auto decoded_update = decode<Update>(raw_update.value());
  if (!decoded_update.ok())
    refuse("native update");
  auto before = accepted_.state().remaining();
  // Applied against the accepted prefix, never against a prefix a failed
  // transaction left behind.
  auto next = accepted_.apply_transaction(decoded_update.value(), admitted_, context_, reader_);
  if (!next.ok())
    refuse("native update refused");

  auto encoded = next.value().state().checkpoint();
  if (!encoded.ok())
    refuse("native registry checkpoint");

  auto after = next.value().state().remaining();
  charge(as_gas(consumed(before, after, gas_per_entry_, gas_per_byte_)));
  // Applying advances the state's budget, so the binding meter follows it.
  work_remaining_ = after;
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
  auto before = work_remaining_;
  auto checkpoint = accepted_.state().checkpoint();
  if (!checkpoint.ok())
    refuse("native registry checkpoint");
  // Opened with what this transaction has left, not with a fresh allowance, so
  // a second binding starts where the first stopped.
  auto registry = RegistryView::open(checkpoint.value(), coordinate_, work_remaining_);
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

  // Taken back from the view, which is where the reads actually happened. The
  // state's own budget is untouched by them, so reading it here reported no
  // work regardless of how much was done.
  work_remaining_ = registry.value().remaining();
  charge(as_gas(consumed(before, work_remaining_, gas_per_entry_, gas_per_byte_)));
  ++bindings_;
  return bound.value();
}
}  // namespace tos::auth
