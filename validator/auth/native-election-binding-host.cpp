#include "block/block-auto.h"

#include "native-election-binding-host.h"
#include "native-election-binding.h"
#include "native-host-charge.h"
#include "registry-view.h"
namespace tos::auth {

td::Ref<vm::Cell> NativeElectionBindingHost::checkpoint(const Charge&) {
  // An elector transaction has no registry update to stage, so it has no
  // checkpoint to read. Refusing as the absent host does keeps the answer the
  // same whether a contract reached this path without an authority or with the
  // wrong one.
  refuse_instruction("P0 native transaction context required");
}

td::Ref<vm::Cell> NativeElectionBindingHost::apply(td::Ref<vm::Cell>, td::Ref<vm::Cell>, const Charge&) {
  refuse_instruction("P0 native transaction context required");
}

td::Ref<vm::Cell> NativeElectionBindingHost::bind(td::Ref<vm::Cell> elected, td::Ref<vm::Cell> bindings,
                                                  const Charge& charge) {
  if (elected.is_null() || bindings.is_null())
    refuse_host("native binding operand");

  auto before = work_remaining_;
  // The registry state cell, which is what a view decodes. The checkpoint
  // beside it is the account's own persistence shape and is refused here.
  auto encoded = accepted_.state().encode_cell();
  if (!encoded.ok())
    refuse_host("native registry state");
  // Opened with what this transaction has left, not with a fresh allowance, so
  // a second binding starts where the first stopped.
  auto registry = RegistryView::open(encoded.value(), coordinate_, work_remaining_);
  if (!registry.ok())
    // Carrying the cause rather than replacing it: "unreadable" alone cannot
    // distinguish a malformed checkpoint from a coordinate the registry has no
    // policy for, and the two are diagnosed differently.
    throw vm::VmError{vm::Excno::cell_und, "native registry unreadable: " + registry.error().code};

  block::gen::ValidatorSet::Record_validators_ext set;
  if (!tlb::unpack_cell(elected, set))
    refuse_host("native binding set");
  auto declared = decode_elected_bindings(std::move(bindings), set.total);
  if (!declared.ok())
    refuse_host("native binding encoding");

  auto bound = bind_elected_validators(std::move(elected), declared.value(), registry.value(), coordinate_);
  if (!bound.ok())
    refuse_host("native binding refused");

  // Taken back from the view, which is where the reads actually happened. The
  // state's own budget is untouched by them, so reading it here reported no
  // work regardless of how much was done.
  work_remaining_ = registry.value().remaining();
  charge(as_gas(consumed(before, work_remaining_, gas_per_entry_, gas_per_byte_)));
  ++bindings_;
  return bound.value();
}
}  // namespace tos::auth
