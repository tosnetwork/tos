#include "block/block-auto.h"
#include "block/block-parse.h"
#include "vm/excno.hpp"
#include "vm/vmstate.h"

#include "cells.h"
#include "codec.h"
#include "native-config-host.h"
#include "native-host-charge.h"
namespace tos::auth {

td::Ref<vm::Cell> NativeConfigHost::checkpoint(const Charge& charge) {
  auto before = accepted_.state().remaining();
  auto encoded = accepted_.state().checkpoint();
  if (!encoded.ok())
    refuse_host("native registry checkpoint");
  auto after = accepted_.state().remaining();
  charge(as_gas(consumed(before, after, gas_per_entry_, gas_per_byte_)));
  ++checkpoints_;
  return encoded.value();
}

td::Ref<vm::Cell> NativeConfigHost::apply(td::Ref<vm::Cell> update, td::Ref<vm::Cell> evidence, const Charge& charge) {
  if (update.is_null() || evidence.is_null())
    refuse_host("native update operand");

  auto raw_update = unpack_bytes(std::move(update));
  if (!raw_update.ok())
    refuse_host("native update encoding");
  // The operand must be the evidence this transaction was admitted with. It is
  // the same reference the contract received, so recognising it is the whole
  // check; decoding it again would make the instruction a second authority on
  // what the transaction carried, reading a container as though it were the
  // authorizations inside it.
  if (admitted_evidence_.is_null() || evidence->get_hash() != admitted_evidence_->get_hash())
    refuse_host("native evidence operand");

  auto decoded_update = decode<Update>(raw_update.value());
  if (!decoded_update.ok())
    refuse_host("native update");
  auto before = accepted_.state().remaining();
  // Applied against the accepted prefix, never against a prefix a failed
  // transaction left behind.
  auto performed = before;
  auto next = accepted_.apply_transaction(decoded_update.value(), admitted_, context_, reader_, &performed);
  // Charged for what the attempt read, before knowing whether it was accepted.
  // A refusal rolls the registry back; it does not roll back the work, or a
  // caller could read the registry for free by arranging to fail at the end.
  charge(as_gas(consumed(before, performed, gas_per_entry_, gas_per_byte_)));
  if (!next.ok())
    refuse_host("native update refused");

  // The registry state, not the checkpoint beside it. The contract installs
  // exactly what this returns as configuration parameter 46, and every reader
  // of that parameter -- the next block's registry, finalized history,
  // committee derivation, owner proofs, the chain context -- decodes the state
  // cell. A checkpoint there would be refused by all of them at once, and the
  // registry would become unreadable one block after the first update.
  //
  // The checkpoint has its own home: the configuration account's data, which
  // the state instruction returns and native commit installs.
  auto encoded = next.value().state().encode_cell();
  if (!encoded.ok())
    refuse_host("native registry state");

  // Staged only after every step succeeded, so a refusal above cannot have
  // advanced the prefix.
  accepted_ = std::move(next.value());
  ++updates_;
  return encoded.value();
}

td::Ref<vm::Cell> NativeConfigHost::bind(td::Ref<vm::Cell>, td::Ref<vm::Cell>, const Charge&) {
  // A registry update is not an election. This host is built for an external
  // message carrying evidence; the set an elector produces is bound by the host
  // built for that message, which implements nothing else. Refusing as the
  // absent host does keeps one answer for "this instruction is not for you".
  refuse_instruction("P0 native transaction context required");
}
}  // namespace tos::auth
