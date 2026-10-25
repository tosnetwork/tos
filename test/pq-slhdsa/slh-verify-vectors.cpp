/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// SLH-DSA-SHA2-128s verification through the node's adapter, in whichever SHA-256 backend this
// build selected. Every fixture signature must verify; flipping one byte of the randomizer, of
// the last hypertree layer, or of the message must not. Checks stay on under NDEBUG.
// Usage: test-pq-slhdsa-vectors <slh-verify-vectors.txt>
// TOS_REQUIRE_SHA_NI=1 also requires the SHA-NI path to be the one executing.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>

#include "slhdsa128s.h"

#define CHECK(cond)                                                                 \
  do {                                                                              \
    if (!(cond)) {                                                                  \
      std::fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
      std::exit(1);                                                                 \
    }                                                                               \
  } while (0)

namespace {
std::string from_hex(const std::string& hex) {
  CHECK(hex.size() % 2 == 0);
  std::string out;
  out.reserve(hex.size() / 2);
  for (std::size_t i = 0; i < hex.size(); i += 2) {
    char* end = nullptr;
    const std::string byte = hex.substr(i, 2);
    const long value = std::strtol(byte.c_str(), &end, 16);
    CHECK(end == byte.c_str() + 2);
    out.push_back(static_cast<char>(value));
  }
  return out;
}

tos::pq::VerifyResult verify(const std::string& m, const std::string& ctx, const std::string& sig,
                             const std::string& pk) {
  return tos::pq::verify_slhdsa128s(m, ctx, sig, pk);
}
}  // namespace

int main(int argc, char** argv) {
  CHECK(argc == 2);
  const char* backend = tos::pq::slhdsa128s_sha256_backend();
  std::printf("SLH-DSA SHA-256 backend: %s\n", backend);
  const char* require = std::getenv("TOS_REQUIRE_SHA_NI");
  if (require != nullptr && std::strcmp(require, "1") == 0) {
    CHECK(std::strcmp(backend, "sha-ni") == 0);
  }

  std::ifstream in(argv[1]);
  CHECK(in.good());
  std::string line;
  int vectors = 0;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') {
      continue;
    }
    std::istringstream fields(line);
    std::string pk_hex, ctx_hex, msg_hex, sig_hex, extra;
    CHECK(static_cast<bool>(fields >> pk_hex >> ctx_hex >> msg_hex >> sig_hex));
    CHECK(!(fields >> extra));
    const auto pk = from_hex(pk_hex);
    const auto ctx = from_hex(ctx_hex);
    const auto msg = from_hex(msg_hex);
    const auto sig = from_hex(sig_hex);
    CHECK(pk.size() == tos::pq::slhdsa128s_public_key_bytes);
    CHECK(sig.size() == tos::pq::slhdsa128s_signature_bytes);

    CHECK(verify(msg, ctx, sig, pk) == tos::pq::VerifyResult::valid);
    for (std::size_t at : {std::size_t{0}, sig.size() - 1}) {
      auto bad = sig;
      bad[at] = static_cast<char>(bad[at] ^ 1);
      CHECK(verify(msg, ctx, bad, pk) == tos::pq::VerifyResult::invalid);
    }
    auto other = msg;
    other[0] = static_cast<char>(other[0] ^ 1);
    CHECK(verify(other, ctx, sig, pk) == tos::pq::VerifyResult::invalid);
    ++vectors;
  }
  CHECK(vectors == 4);
  std::printf("OK: %d vectors verified, 12 corruptions rejected\n", vectors);
  return 0;
}
