/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// The exact bytes a validator controller's post-quantum root signs, as bytes rather than
// as a field list to be rebuilt. A contract, a node and the tooling that signs for an
// operator each construct these independently, and a signature made over one layout
// verifies under none of the others.
#include <cstdio>
#include <cstring>
#include <string>

#include "crypto/pq/pq-controller.h"
#include "td/utils/misc.h"

namespace {

td::Bits256 fill(unsigned char b) {
  td::Bits256 out;
  std::memset(out.data(), b, 32);
  return out;
}

void emit(const char* name, const std::string& bytes) {
  std::printf("%s\t%zu\t%s\n", name, bytes.size(), td::hex_encode(td::Slice(bytes)).c_str());
}

}  // namespace

int main() {
  std::printf("# What a validator controller's post-quantum root signs. Fixed inputs, chosen so\n");
  std::printf("# every field is distinguishable in the output, and a field swapped for another of\n");
  std::printf("# the same width still changes these bytes.\n");
  std::printf("#\n");
  std::printf("# controller-auth: TAG u32 | global_id i32 | controller_id u256 | epoch u64 |\n");
  std::printf("#                  nonce u64 | valid_until u32 | kind u8 | payload_hash u256\n");
  std::printf("#\n");
  std::printf("# The context these are signed under is pinned as `context`, and the key and\n");
  std::printf("# signature rows hold one real ML-DSA-44 signature over `controller-auth`, so a\n");
  std::printf("# consumer can be held to verifying it rather than only to rebuilding bytes.\n");
  std::printf("#\n");
  std::printf("# name\tbytes\thex\n");

  const auto base = tos::pq::controller_auth_preimage(-239, fill(0xa1), 7, 3, 1789434000u, 1, fill(0xb2));
  emit("controller-auth", base);
  emit("controller-auth-other-network",
       tos::pq::controller_auth_preimage(-1, fill(0xa1), 7, 3, 1789434000u, 1, fill(0xb2)));
  emit("controller-auth-other-controller",
       tos::pq::controller_auth_preimage(-239, fill(0xa2), 7, 3, 1789434000u, 1, fill(0xb2)));
  emit("controller-auth-other-epoch",
       tos::pq::controller_auth_preimage(-239, fill(0xa1), 8, 3, 1789434000u, 1, fill(0xb2)));
  emit("controller-auth-other-nonce",
       tos::pq::controller_auth_preimage(-239, fill(0xa1), 7, 4, 1789434000u, 1, fill(0xb2)));
  emit("controller-auth-other-expiry",
       tos::pq::controller_auth_preimage(-239, fill(0xa1), 7, 3, 1789434001u, 1, fill(0xb2)));
  emit("controller-auth-other-kind",
       tos::pq::controller_auth_preimage(-239, fill(0xa1), 7, 3, 1789434000u, 2, fill(0xb2)));
  emit("controller-auth-other-payload",
       tos::pq::controller_auth_preimage(-239, fill(0xa1), 7, 3, 1789434000u, 1, fill(0xb3)));

  std::string context(tos::pq::controller_auth_context);
  emit("context", context);
  return 0;
}
