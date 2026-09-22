/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */

// Provisioning for the one post-quantum secret a validator host holds.
//
// The node reads its consensus key from a file it does not create. This puts one there,
// puts a saved one back, or says which key a file already holds -- under exactly the
// rules the node loads it by, so a key this reports as written is one the node will
// accept, and a key it refuses is one the node would have refused at startup.
//
// There is no command that prints the seed or the expanded secret. Restoring a key needs
// the backup the operator took when they generated it; this tool is not that backup.

#include <cstdio>
#include <cstring>
#include <openssl/crypto.h>
#include <string>
#include <string_view>
#include <variant>

#include "consensus-key-file.h"

namespace {

void print_hex(std::string_view bytes) {
  static const char digits[] = "0123456789abcdef";
  for (unsigned char c : bytes) {
    std::fputc(digits[c >> 4], stdout);
    std::fputc(digits[c & 15], stdout);
  }
}

// What a validator set records for this key, and nothing else. The identity is derived
// from the file every time rather than remembered, because the point of printing it is
// to compare it against what the chain says.
void report(const tos::pq::ConsensusPQKey& key) {
  std::fputs("algorithm mldsa44\nkey_id    ", stdout);
  print_hex(std::string_view(reinterpret_cast<const char*>(key.key_id.data()), key.key_id.size()));
  std::fputs("\npublic    ", stdout);
  print_hex(key.public_key);
  std::fputc('\n', stdout);
}

int refuse(tos::pq::ConsensusKeyFileError error, std::string_view path) {
  std::fprintf(stderr, "%.*s: %s\n", static_cast<int>(path.size()), path.data(), tos::pq::describe(error));
  return 1;
}

// A seed arrives as hexadecimal on standard input, never as an argument: an argument is
// visible to every process on the host for as long as this one runs.
//
// Whitespace is allowed around the digits and nowhere else. Allowing it between them
// would mean a seed could be written in more than one way, and two operators comparing
// what they typed against what a key derives would have no reason to expect the same
// answer.
bool read_seed_hex(std::string& seed) {
  constexpr std::size_t digits = 2 * tos::pq::consensus_seed_bytes;
  // Every ASCII space, not a chosen few: a seed pasted from a file that ends in a form
  // feed is the same seed, and refusing it would be a rule about the operator's editor.
  auto is_space = [](int c) { return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'; };

  std::string text;
  bool ended = false;  // whitespace after the digits: nothing may follow it
  int c;
  while ((c = std::fgetc(stdin)) != EOF) {
    if (is_space(c)) {
      ended = !text.empty();
      continue;
    }
    if (ended || text.size() >= digits) {
      OPENSSL_cleanse(text.data(), text.size());
      return false;
    }
    text.push_back(static_cast<char>(c));
  }
  if (text.size() != digits) {
    OPENSSL_cleanse(text.data(), text.size());
    return false;
  }
  auto nibble = [](char h) -> int {
    if (h >= '0' && h <= '9') {
      return h - '0';
    }
    if (h >= 'a' && h <= 'f') {
      return h - 'a' + 10;
    }
    if (h >= 'A' && h <= 'F') {
      return h - 'A' + 10;
    }
    return -1;
  };
  seed.assign(tos::pq::consensus_seed_bytes, '\0');
  for (std::size_t i = 0; i < tos::pq::consensus_seed_bytes; i++) {
    const int hi = nibble(text[2 * i]);
    const int lo = nibble(text[2 * i + 1]);
    if (hi < 0 || lo < 0) {
      OPENSSL_cleanse(text.data(), text.size());
      OPENSSL_cleanse(seed.data(), seed.size());
      return false;
    }
    seed[i] = static_cast<char>(hi * 16 + lo);
  }
  OPENSSL_cleanse(text.data(), text.size());
  return true;
}

int usage() {
  std::fputs(
      "usage: tos-pq-consensus-key generate KEYFILE\n"
      "       tos-pq-consensus-key import KEYFILE   (64 hex characters on stdin)\n"
      "       tos-pq-consensus-key show KEYFILE\n"
      "\n"
      "Each command prints the identity the validator set records for the key.\n"
      "None of them can print the key itself.\n",
      stderr);
  return 2;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 3) {
    return usage();
  }
  const std::string_view command(argv[1]);
  const std::string_view path(argv[2]);

  if (command == "generate") {
    auto made = tos::pq::create_consensus_key(path);
    if (std::holds_alternative<tos::pq::ConsensusKeyFileError>(made)) {
      return refuse(std::get<tos::pq::ConsensusKeyFileError>(made), path);
    }
    report(std::get<tos::pq::ConsensusPQKey>(made));
    return 0;
  }

  if (command == "import") {
    std::string seed;
    if (!read_seed_hex(seed)) {
      std::fputs("a consensus key is 64 hexadecimal characters, and nothing but space around them\n", stderr);
      return 1;
    }
    auto placed = tos::pq::import_consensus_key(path, seed);
    OPENSSL_cleanse(seed.data(), seed.size());
    if (std::holds_alternative<tos::pq::ConsensusKeyFileError>(placed)) {
      return refuse(std::get<tos::pq::ConsensusKeyFileError>(placed), path);
    }
    report(std::get<tos::pq::ConsensusPQKey>(placed));
    return 0;
  }

  if (command == "show") {
    auto loaded = tos::pq::load_consensus_key(path);
    if (std::holds_alternative<tos::pq::ConsensusKeyFileError>(loaded)) {
      return refuse(std::get<tos::pq::ConsensusKeyFileError>(loaded), path);
    }
    report(std::get<tos::pq::ValidatorPQKeyStore>(loaded).consensus_key());
    return 0;
  }

  return usage();
}
