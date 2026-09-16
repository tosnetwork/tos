#include "native-config-state-host.h"
#include "native-host-charge.h"
namespace tos::auth {

td::Ref<vm::Cell> NativeConfigStateHost::checkpoint(const Charge& charge) {
  auto before = accepted_.state().remaining();
  auto encoded = accepted_.state().checkpoint();
  if (!encoded.ok())
    refuse_host("native registry checkpoint");
  auto after = accepted_.state().remaining();
  charge.gas(as_gas(consumed(before, after, gas_per_entry_, gas_per_byte_)));
  ++checkpoints_;
  return encoded.value();
}

td::Ref<vm::Cell> NativeConfigStateHost::apply(td::Ref<vm::Cell>, td::Ref<vm::Cell>, const Charge&) {
  // A tick-tock carries no message and no evidence, so there is no update to
  // apply and nothing that could authorize one.
  refuse_instruction("P0 native transaction context required");
}

td::Ref<vm::Cell> NativeConfigStateHost::bind(td::Ref<vm::Cell>, td::Ref<vm::Cell>, const Charge&) {
  refuse_instruction("P0 native transaction context required");
}

Result<std::unique_ptr<NativeConfigStateTransaction>> NativeConfigStateTransaction::open(
    const NativeConfigSequence& sequence, const Hash& account) {
  if (account != sequence.address())
    return Error{"native-state-transaction-account"};
  return std::unique_ptr<NativeConfigStateTransaction>(new NativeConfigStateTransaction(sequence.accepted()));
}
}  // namespace tos::auth
