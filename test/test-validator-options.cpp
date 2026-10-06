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
  return 0;
}
