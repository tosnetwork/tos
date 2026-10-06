/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "validator/validator.h"

#include <cstdio>
#include <string>
#include <utility>

#include "td/utils/misc.h"

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
  if (options->get_ext_message_work_profile()) {
    std::fprintf(stderr, "uncalibrated admission work profile enabled by default\n");
    return 1;
  }
  tos::validator::ExtMessageWorkProfile profile;
  if (options.write().set_ext_message_work_profile(profile).is_ok() || options->get_ext_message_work_profile()) {
    std::fprintf(stderr, "invalid admission profile was installed\n");
    return 1;
  }
  profile.config_root.data()[0] = 1;
  profile.capacity = 2;
  profile.refill_units = 1;
  profile.refill_interval_ns = 1000000000;
  profile.attempt_units = 1;
  profile.max_bytes = 65535;
  profile.max_depth = 512;
  if (options.write().set_ext_message_work_profile(profile).is_error() || !options->get_ext_message_work_profile()) {
    std::fprintf(stderr, "valid explicit admission profile was not installed\n");
    return 1;
  }
  auto invalid = profile;
  invalid.attempt_units = 3;
  if (options.write().set_ext_message_work_profile(invalid).is_ok() ||
      options->get_ext_message_work_profile().value().attempt_units != 1) {
    std::fprintf(stderr, "invalid update changed the installed admission profile\n");
    return 1;
  }
  const auto hash = td::hex_encode(profile.config_root.as_slice());
  auto parsed = tos::validator::ExtMessageWorkProfile::parse(hash + ",2,1,1000000000,1,65535,512");
  if (parsed.is_error() || parsed.ok().config_root != profile.config_root || parsed.ok().capacity != 2 ||
      parsed.ok().refill_units != 1 || parsed.ok().refill_interval_ns != 1000000000 ||
      parsed.ok().attempt_units != 1 || parsed.ok().max_bytes != 65535 || parsed.ok().max_depth != 512) {
    std::fprintf(stderr, "valid admission CLI profile did not preserve fields\n");
    return 1;
  }
  const std::pair<const char*, std::string> malformed[] = {
      {"zero-root", std::string(64, '0') + ",2,1,1000000000,1,65535,512"},
      {"zero-capacity", hash + ",0,1,1000000000,1,65535,512"},
      {"zero-refill", hash + ",2,0,1000000000,1,65535,512"},
      {"zero-interval", hash + ",2,1,0,1,65535,512"},
      {"quote-over-capacity", hash + ",2,1,1000000000,3,65535,512"},
      {"capacity-overflow", hash + ",18446744073709551616,1,1000000000,1,65535,512"},
      {"bytes-overflow", hash + ",2,1,1000000000,1,4294967296,512"},
      {"leading-zero", hash + ",02,1,1000000000,1,65535,512"},
      {"negative", hash + ",-2,1,1000000000,1,65535,512"},
      {"fraction", hash + ",2.0,1,1000000000,1,65535,512"},
      {"exponent", hash + ",2e0,1,1000000000,1,65535,512"},
      {"whitespace", hash + ", 2,1,1000000000,1,65535,512"},
      {"extra-field", hash + ",2,1,1000000000,1,65535,512,9"},
      {"empty-field", hash + ",2,,1000000000,1,65535,512"},
      {"uppercase-hash", std::string(64, 'A') + ",2,1,1000000000,1,65535,512"},
      {"short-hash", hash.substr(1) + ",2,1,1000000000,1,65535,512"},
      {"nonhex-hash", std::string(64, 'g') + ",2,1,1000000000,1,65535,512"},
      {"oversized", std::string(257, '0')},
  };
  for (const auto& item : malformed) {
    if (tos::validator::ExtMessageWorkProfile::parse(item.second).is_ok()) {
      std::fprintf(stderr, "invalid admission CLI profile accepted: %s\n", item.first);
      return 1;
    }
  }
  return 0;
}
