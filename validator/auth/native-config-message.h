#pragma once
#include "vm/cells/Cell.h"

#include "codec.h"
namespace tos::auth {
// The action the configuration contract answers for an authenticated registry
// update. Defined once here and used by both the recognizer and whatever
// composes such a message, so the tag is not written down twice.
inline constexpr std::uint32_t native_registry_action = 0x56417531;

// The action the configuration contract answers for an elected validator set,
// written once for the same reason.
inline constexpr std::uint32_t native_validator_set_action = 0x4e565354;

struct NativeRegistryMessage {
  td::Ref<vm::Cell> update;
  td::Ref<vm::Cell> evidence;
  // The exact configuration proposal a governance operation finalizes, when the
  // message carries one. It is a separate attachment rather than a field of the
  // update: the update names it by hash, and the proposal that has already
  // passed the normal vote is the object those hashes have to match.
  td::Ref<vm::Cell> proposal;
};

// Recognise a registry update in an inbound external message body.
//
// This is the seam between the contract's message shape and the node: the node
// has to know, before executing anything, whether a message is one of these, so
// that it can assemble the authority the execution will run under. Recognising
// it is not admitting it -- the instruction still validates the update's
// authorizations, and this refuses to decide anything about them.
//
// The body is untrusted. It is parsed to the exact shape the contract parses
// and refused otherwise, so a message that merely resembles one cannot cause
// work to be done on its behalf.
Result<NativeRegistryMessage> recognize_registry_message(td::Ref<vm::Cell> body);

struct NativeElectionSetMessage {
  td::Ref<vm::Cell> elected;
  td::Ref<vm::Cell> bindings;
};

// Recognise an elected validator set in an inbound internal message body.
//
// The same seam as above, for the other message the configuration contract
// answers. The bindings reference is optional in the contract, so it is
// optional here; whether a set may arrive without one is activation's question
// and is answered where the authority is assembled, not by the parser.
Result<NativeElectionSetMessage> recognize_validator_set_message(td::Ref<vm::Cell> body);
}  // namespace tos::auth
