/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include "controller-root-file.h"
#include "seed-file.h"

namespace tos::pq {
namespace {

ControllerRootFileError as_root_error(detail::SeedFileRefusal refusal) noexcept {
  switch (refusal) {
    case detail::SeedFileRefusal::cannot_open:
      return ControllerRootFileError::cannot_open;
    case detail::SeedFileRefusal::not_a_regular_file:
      return ControllerRootFileError::not_a_regular_file;
    case detail::SeedFileRefusal::wrong_owner:
      return ControllerRootFileError::wrong_owner;
    case detail::SeedFileRefusal::readable_by_others:
      return ControllerRootFileError::readable_by_others;
    case detail::SeedFileRefusal::directory_writable:
      return ControllerRootFileError::directory_writable;
    case detail::SeedFileRefusal::wrong_size:
      return ControllerRootFileError::wrong_size;
    case detail::SeedFileRefusal::read_failed:
      return ControllerRootFileError::read_failed;
  }
  return ControllerRootFileError::read_failed;
}

}  // namespace

const char* describe(ControllerRootFileError error) noexcept {
  switch (error) {
    case ControllerRootFileError::cannot_open:
      return "cannot be opened: it is absent, unreadable, or a symbolic link";
    case ControllerRootFileError::not_a_regular_file:
      return "is not a regular file";
    case ControllerRootFileError::wrong_owner:
      return "is owned by another user";
    case ControllerRootFileError::readable_by_others:
      return "can be read by its group or by everyone";
    case ControllerRootFileError::directory_writable:
      return "sits in a directory its group or everyone can write";
    case ControllerRootFileError::wrong_size:
      return "is not exactly 32 bytes, so it is not a root seed";
    case ControllerRootFileError::read_failed:
      return "could not be read to the end";
    case ControllerRootFileError::derivation_failed:
      return "holds 32 bytes the post-quantum backend refused";
  }
  return "could not be read";
}

std::variant<ValidatorControllerRootKeyStore, ControllerRootFileError> load_controller_root_key(
    std::string_view path) noexcept {
  detail::SeedBuffer seed;
  if (auto refused = detail::read_protected_seed(path, seed)) {
    return as_root_error(*refused);
  }
  auto store = ValidatorControllerRootKeyStore::from_seed(
      std::string_view(reinterpret_cast<const char*>(seed.bytes.data()), seed.bytes.size()));
  if (!store.has_value()) {
    return ControllerRootFileError::derivation_failed;
  }
  // The seed buffer is wiped by its destructor here; what survives is the signer, whose
  // own destructor wipes the expanded secret.
  return std::move(*store);
}

}  // namespace tos::pq
