/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "validator/validator.h"

#include <cstdio>

int main() {
  auto options = tos::validator::ValidatorManagerOptions::create(tos::BlockIdExt{}, tos::BlockIdExt{});
  const auto expected = tos::validator::ValidatorManagerOptions::default_max_open_archive_files();
  if (expected == 0 || options->get_max_open_archive_files() != expected) {
    std::fprintf(stderr, "archive FD limit default is not active\n");
    return 1;
  }

  options.write().set_max_open_archive_files(0);
  if (options->get_max_open_archive_files() != 0) {
    std::fprintf(stderr, "archive FD unlimited override was not preserved\n");
    return 1;
  }

  options.write().set_max_open_archive_files(128);
  if (options->get_max_open_archive_files() != 128) {
    std::fprintf(stderr, "archive FD explicit limit was not preserved\n");
    return 1;
  }

  // Retired validator consensus databases are deleted by default; without it a
  // validator's disk grows by one RocksDB directory per session forever.
  if (!options->get_validator_consensus_cleanup_enabled()) {
    std::fprintf(stderr, "validator consensus cleanup is not on by default\n");
    return 1;
  }
  options.write().set_validator_consensus_cleanup_enabled(false);
  if (options->get_validator_consensus_cleanup_enabled()) {
    std::fprintf(stderr, "validator consensus cleanup opt-out was not preserved\n");
    return 1;
  }
  // The crash fault injection is test-only and must never be armed by default.
  if (options->get_test_crash_cleanup_before_erase()) {
    std::fprintf(stderr, "cleanup crash fault injection is armed by default\n");
    return 1;
  }
  return 0;
}
