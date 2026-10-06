// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
#include "td/utils/misc.h"

#include "admission-work-profile.h"

namespace tos::validator {

td::Result<ExtMessageWorkProfile> ExtMessageWorkProfile::parse(td::Slice text) {
  if (text.size() > 256) {
    return td::Status::Error("external admission work profile is too long");
  }
  auto fields = td::full_split(text, ',', 8);
  if (fields.size() != 7 || fields[0].size() != 64) {
    return td::Status::Error("external admission work profile requires a 64-digit config hash and six integers");
  }
  for (char c : fields[0]) {
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
      return td::Status::Error("external admission config hash must be lowercase hexadecimal");
    }
  }
  ExtMessageWorkProfile profile;
  TRY_RESULT(hash, td::hex_decode(fields[0]));
  profile.config_root.as_slice().copy_from(td::Slice(hash));
  TRY_RESULT(capacity, td::to_integer_safe<std::uint64_t>(fields[1]));
  TRY_RESULT(refill, td::to_integer_safe<std::uint64_t>(fields[2]));
  TRY_RESULT(interval, td::to_integer_safe<std::uint64_t>(fields[3]));
  TRY_RESULT(attempt, td::to_integer_safe<std::uint64_t>(fields[4]));
  TRY_RESULT(bytes, td::to_integer_safe<std::uint32_t>(fields[5]));
  TRY_RESULT(depth, td::to_integer_safe<std::uint32_t>(fields[6]));
  profile.capacity = capacity;
  profile.refill_units = refill;
  profile.refill_interval_ns = interval;
  profile.attempt_units = attempt;
  profile.max_bytes = bytes;
  profile.max_depth = depth;
  TRY_STATUS(profile.validate());
  return profile;
}

}  // namespace tos::validator
