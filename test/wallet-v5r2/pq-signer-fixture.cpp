/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// PUBLIC TEST KEYS ONLY. Never use this fixture executable for custody or funds.
#include <cstdio>
#include <string>
#include <string_view>

#include "wallet-pq-signer.h"
using namespace tos::pq;
static std::string hex(std::string_view bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  for (unsigned char c : bytes) {
    result += digits[c >> 4];
    result += digits[c & 15];
  }
  return result;
}
int main(int argc, char** argv) {
  if (argc != 5 || std::string_view(argv[1]) != "--public-fixture")
    return 2;
  const std::string_view key = argv[2], purpose_name = argv[3], encoded = argv[4];
  WalletPQRole role;
  unsigned char seed_byte;
  if (key == "primary") {
    role = WalletPQRole::primary;
    seed_byte = 0x11;
  } else if (key == "next-primary") {
    role = WalletPQRole::primary;
    seed_byte = 0x99;
  } else if (key == "rescue") {
    role = WalletPQRole::rescue;
    seed_byte = 0x22;
  } else if (key == "next-rescue") {
    role = WalletPQRole::rescue;
    seed_byte = 0x33;
  } else
    return 2;
  WalletPQPurpose purpose;
  if (purpose_name == "auth")
    purpose = WalletPQPurpose::auth;
  else if (purpose_name == "pop")
    purpose = WalletPQPurpose::pop;
  else if (purpose_name == "preparation")
    purpose = WalletPQPurpose::preparation;
  else
    return 2;
  if (encoded.size() != 64)
    return 2;
  auto nibble = [](char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1; };
  std::string digest;
  for (std::size_t i = 0; i < encoded.size(); i += 2) {
    int hi = nibble(encoded[i]), lo = nibble(encoded[i + 1]);
    if (hi < 0 || lo < 0)
      return 2;
    digest.push_back(static_cast<char>((hi << 4) | lo));
  }
  auto signer = WalletPQSigner::from_seed(
      role, std::string(role == WalletPQRole::primary ? 32 : 48, static_cast<char>(seed_byte)));
  if (!signer)
    return 3;
  auto signature = signer->sign(purpose, digest);
  if (!signature)
    return 4;
  std::printf("{\"public_key\":\"%s\",\"signature\":\"%s\"}\n", hex(signer->public_key()).c_str(),
              hex(*signature).c_str());
}
