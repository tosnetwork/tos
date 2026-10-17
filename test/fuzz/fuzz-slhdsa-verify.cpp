/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// SLH-DSA-SHA2-128s verification (verify_slhdsa128s), the entry the TVM opcode reaches with
// a contract's key, signature, message and context.
//
// Input layout: a u8 context length and that many context bytes, then the public key, then
// the signature, then the message; a field cut short by the end of the input is passed
// short, so lengths other than the scheme's own reach the verifier too.
//
// Verification must be deterministic, and an accepted signature must not verify for any
// other message or context: the input's message and context are each altered by one bit
// and checked again.
//
// Run:
//   build-fuzz/fuzz/fuzz-slhdsa-verify -max_total_time=300 -max_len=16384 fuzz-work/fuzz-slhdsa-verify test/fuzz/corpus/fuzz-slhdsa-verify

#include <string>
#include <string_view>

#include "crypto/pq/slhdsa128s.h"

#include "fuzz-common.h"

namespace {

std::string_view view(td::Slice slice) {
  return {slice.data(), slice.size()};
}

}  // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  tos::fuzz::quiet_logging();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  using tos::pq::VerifyResult;
  tos::fuzz::Reader in(data, size);
  auto context = in.bytes(in.u8());
  auto public_key = in.bytes(tos::pq::slhdsa128s_public_key_bytes);
  auto signature = in.bytes(tos::pq::slhdsa128s_signature_bytes);
  auto message = in.rest();

  auto result = tos::pq::verify_slhdsa128s(view(message), view(context), view(signature), view(public_key));
  TOS_FUZZ_INVARIANT(result != VerifyResult::backend_error);
  TOS_FUZZ_INVARIANT(result ==
                     tos::pq::verify_slhdsa128s(view(message), view(context), view(signature), view(public_key)));
  if (result != VerifyResult::valid) {
    return 0;
  }
  TOS_FUZZ_INVARIANT(public_key.size() == tos::pq::slhdsa128s_public_key_bytes);
  TOS_FUZZ_INVARIANT(signature.size() == tos::pq::slhdsa128s_signature_bytes);
  TOS_FUZZ_INVARIANT(message.size() <= tos::pq::slhdsa128s_max_message_bytes);

  std::string other_message = message.str();
  if (other_message.empty()) {
    other_message.push_back('\0');
  } else {
    other_message[other_message.size() / 2] ^= 1;
  }
  TOS_FUZZ_INVARIANT(tos::pq::verify_slhdsa128s(other_message, view(context), view(signature), view(public_key)) !=
                     VerifyResult::valid);

  std::string other_context = context.str();
  if (other_context.empty()) {
    other_context.push_back('\0');
  } else {
    other_context[0] ^= 1;
  }
  TOS_FUZZ_INVARIANT(tos::pq::verify_slhdsa128s(view(message), other_context, view(signature), view(public_key)) !=
                     VerifyResult::valid);
  return 0;
}
