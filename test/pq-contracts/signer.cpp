/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
/* TEST ONLY deterministic ML-DSA-44 keys 0..255. The seeds are public: never use them for
   real funds. Reads lines "<key> <message-hex> <context-hex>" on stdin (an empty hex field
   is "-") and writes "<public-key-hex> <signature-hex>" for each, after checking that the
   signature verifies. */
#include "mldsa_native.h"
// The public header undefines its namespace-prefix macro at the end, so name the fixed
// symbols this build configuration declares. Keep in step with signer-config.h; a mismatch
// fails to link rather than silently.
#define PQ_SIGNER_SYM(sym) tos_pq_contracts_test_##sym
#include <array>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

static std::vector<uint8_t> unhex(const std::string& text, std::size_t limit) {
  if (text == "-")
    return {};
  if (text.size() % 2 || text.size() / 2 > limit)
    throw std::runtime_error("invalid hex length");
  auto nibble = [](char c) -> uint8_t {
    if (c >= '0' && c <= '9')
      return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f')
      return static_cast<uint8_t>(c - 'a' + 10);
    throw std::runtime_error("noncanonical hex");
  };
  std::vector<uint8_t> out;
  for (std::size_t i = 0; i < text.size(); i += 2) {
    out.push_back(static_cast<uint8_t>((nibble(text[i]) << 4) | nibble(text[i + 1])));
  }
  return out;
}

template <std::size_t N>
static std::string hex(const std::array<uint8_t, N>& data) {
  constexpr char digits[] = "0123456789abcdef";
  std::string out;
  for (uint8_t c : data) {
    out += digits[c >> 4];
    out += digits[c & 15];
  }
  return out;
}

int main() {
  try {
    std::string line;
    while (std::getline(std::cin, line)) {
      std::istringstream fields(line);
      int key = -1;
      std::string message_hex, context_hex;
      if (!(fields >> key >> message_hex >> context_hex) || key < 0 || key > 255) {
        throw std::runtime_error("TEST ONLY: expected '<key 0..255> <message-hex|-> <context-hex|->'");
      }
      const auto message = unhex(message_hex, 8192);
      const auto context = unhex(context_hex, 255);
      std::array<uint8_t, MLDSA_SEEDBYTES> seed{};
      seed.fill(static_cast<uint8_t>(key));
      seed[0] = 0x5a;  // keeps these keys apart from the auth-module test keys
      std::array<uint8_t, MLDSA44_PUBLICKEYBYTES> pk{};
      std::array<uint8_t, MLDSA44_SECRETKEYBYTES> sk{};
      std::array<uint8_t, MLDSA44_BYTES> sig{};
      std::array<uint8_t, MLDSA_RNDBYTES> rnd{};
      if (PQ_SIGNER_SYM(keypair_internal)(pk.data(), sk.data(), seed.data()) != 0) {
        throw std::runtime_error("key generation failed");
      }
      // FIPS 204 Pure external interface: 0x00 || len(ctx) || ctx || message. Zero rnd
      // selects deterministic signing.
      std::vector<uint8_t> prefix{0, static_cast<uint8_t>(context.size())};
      prefix.insert(prefix.end(), context.begin(), context.end());
      const int rc = PQ_SIGNER_SYM(signature_internal)(sig.data(), message.data(), message.size(), prefix.data(),
                                                       prefix.size(), rnd.data(), sk.data(), 0);
      volatile uint8_t* wipe = sk.data();
      for (std::size_t i = 0; i < sk.size(); ++i)
        wipe[i] = 0;
      if (rc != 0 || PQ_SIGNER_SYM(verify)(sig.data(), message.data(), message.size(), context.data(), context.size(),
                                           pk.data()) != 0) {
        throw std::runtime_error("sign/verify self-check failed");
      }
      std::cout << hex(pk) << ' ' << hex(sig) << '\n';
    }
    return 0;
  } catch (const std::exception& e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
