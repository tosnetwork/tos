// Recognising a registry update, and refusing everything that merely looks like
// one.
//
// The node has to know before executing whether a message is a registry update,
// so that it can resolve what the execution will read. That makes the
// recognizer a place where an attacker chooses the input: a body that resembles
// one closely enough to be accepted would cause history to be fetched on its
// behalf, and a body accepted with the wrong shape would have its references
// read from whatever followed.
#include <iostream>
#include <stdexcept>

#include "validator/auth/native-config-message.h"

#include "vm/cellslice.h"

using namespace tos::auth;

namespace {
unsigned passed = 0;

void ok(const char* name) {
  ++passed;
  std::cout << "CASE_PASS " << name << '\n';
}

void expect(bool condition, const char* name) {
  if (!condition)
    throw std::runtime_error(name);
}

void refuses(const Result<NativeRegistryMessage>& result, const char* code, const char* name) {
  if (result.ok() || result.error().code != code) {
    std::cerr << "DETAIL " << name << " expected=" << code
              << " actual=" << (result.ok() ? "accepted" : result.error().code) << '\n';
    throw std::runtime_error(name);
  }
  ok(name);
}

td::Ref<vm::Cell> marker(unsigned value) {
  return vm::CellBuilder().store_long(value, 16).finalize();
}

// Built to exactly the shape the contract parses, so a case that changes one
// field is changing that field and nothing else.
td::Ref<vm::Cell> message(std::uint32_t action, unsigned refs = 2, unsigned trailing_bits = 0) {
  vm::CellBuilder b;
  b.store_zeroes(512);        // signature
  b.store_long(action, 32);   // action
  b.store_long(7, 32);        // seqno
  b.store_long(9, 32);        // valid until
  if (trailing_bits)
    b.store_zeroes(trailing_bits);
  if (refs >= 1)
    b.store_ref(marker(0x1111));
  if (refs >= 2)
    b.store_ref(marker(0x2222));
  if (refs >= 3)
    b.store_ref(marker(0x3333));
  // Four is the most a cell holds, so it is the whole of "more than this
  // message has". Without it the extra-reference case asked for four, got
  // three, and tested the proposal attachment instead.
  if (refs >= 4)
    b.store_ref(marker(0x4444));
  return b.finalize();
}
}  // namespace

int main() {
  try {
    auto recognized = recognize_registry_message(message(native_registry_action));
    expect(recognized.ok(), "well-formed-message-recognized");
    expect(recognized.value().update->get_hash() == marker(0x1111)->get_hash(), "well-formed-message-recognized");
    expect(recognized.value().evidence->get_hash() == marker(0x2222)->get_hash(), "well-formed-message-recognized");
    ok("well-formed-message-recognized");

    // Another action with the same shape is not this message.
    refuses(recognize_registry_message(message(0x43665021)), "registry-message-action", "other-action-refused");

    // One reference short: accepting this would read the evidence from
    // somewhere that is not the message.
    refuses(recognize_registry_message(message(native_registry_action, 1)), "registry-message-shape",
            "missing-reference-refused");

    // A third reference is the configuration proposal a governance operation
    // finalizes, so it is recognised rather than refused. Whether one belongs
    // with this operation is decided where the operation is decoded: refusing
    // it here as well would be a second reading of the same update, and the two
    // would be free to disagree about which operations take an attachment.
    {
      auto carried = recognize_registry_message(message(native_registry_action, 3));
      expect(carried.ok() && carried.value().proposal.not_null(), "proposal-reference-recognised");
      ok("proposal-reference-recognised");
    }

    // A fourth is not anything. The contract ends its parse, so a body carrying
    // more is not the body it would accept.
    refuses(recognize_registry_message(message(native_registry_action, 4)), "registry-message-shape",
            "extra-reference-refused");

    refuses(recognize_registry_message(message(native_registry_action, 2, 8)), "registry-message-shape",
            "trailing-bits-refused");

    // Too short to contain the fields the contract reads before the references.
    vm::CellBuilder truncated;
    truncated.store_zeroes(512);
    truncated.store_long(native_registry_action, 32);
    truncated.store_ref(marker(0x1111));
    truncated.store_ref(marker(0x2222));
    refuses(recognize_registry_message(truncated.finalize()), "registry-message-shape", "truncated-body-refused");

    refuses(recognize_registry_message({}), "registry-message-absent", "absent-body-refused");

    std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
