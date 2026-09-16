#pragma once
#include "vm/cells/Cell.h"

#include "codec.h"
namespace tos::auth {
// The action the configuration contract answers for an authenticated registry
// update. Defined once here and used by both the recognizer and whatever
// composes such a message, so the tag is not written down twice.
inline constexpr std::uint32_t native_registry_action = 0x56417531;

struct NativeRegistryMessage {
  td::Ref<vm::Cell> update;
  td::Ref<vm::Cell> evidence;
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
}  // namespace tos::auth
