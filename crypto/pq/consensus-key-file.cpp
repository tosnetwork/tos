/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include "consensus-key-file.h"
#include "seed-file.h"

namespace tos::pq {
namespace {

constexpr std::size_t seed_bytes = consensus_seed_bytes;
static_assert(seed_bytes == detail::seed_file_bytes, "a consensus seed is a seed file");

using detail::Descriptor;
using detail::directory_is_private;
using detail::parent_directory;
using detail::SeedBuffer;

// The shared refusal, in the words this key's operator needs.
ConsensusKeyFileError as_consensus_error(detail::SeedFileRefusal refusal) noexcept {
  switch (refusal) {
    case detail::SeedFileRefusal::cannot_open:
      return ConsensusKeyFileError::cannot_open;
    case detail::SeedFileRefusal::not_a_regular_file:
      return ConsensusKeyFileError::not_a_regular_file;
    case detail::SeedFileRefusal::wrong_owner:
      return ConsensusKeyFileError::wrong_owner;
    case detail::SeedFileRefusal::readable_by_others:
      return ConsensusKeyFileError::readable_by_others;
    case detail::SeedFileRefusal::directory_writable:
      return ConsensusKeyFileError::directory_writable;
    case detail::SeedFileRefusal::wrong_size:
      return ConsensusKeyFileError::wrong_size;
    case detail::SeedFileRefusal::read_failed:
      return ConsensusKeyFileError::read_failed;
  }
  return ConsensusKeyFileError::read_failed;
}

}  // namespace

const char* describe(ConsensusKeyFileError error) noexcept {
  switch (error) {
    case ConsensusKeyFileError::cannot_open:
      return "the consensus key file cannot be opened, or is a symbolic link";
    case ConsensusKeyFileError::not_a_regular_file:
      return "the consensus key path is not a regular file";
    case ConsensusKeyFileError::wrong_owner:
      return "the consensus key file is owned by another user";
    case ConsensusKeyFileError::readable_by_others:
      return "the consensus key file is readable or writable by group or others";
    case ConsensusKeyFileError::directory_writable:
      return "the directory holding the consensus key is writable by group or others";
    case ConsensusKeyFileError::wrong_size:
      return "the consensus key file is not a 32-byte seed";
    case ConsensusKeyFileError::read_failed:
      return "the consensus key file could not be read to its end";
    case ConsensusKeyFileError::derivation_failed:
      return "no key could be derived from the consensus seed";
    case ConsensusKeyFileError::already_exists:
      return "a consensus key is already there; remove it deliberately to replace it";
    case ConsensusKeyFileError::write_failed:
      return "the consensus key could not be written";
  }
  return "the consensus key file was refused";
}

std::variant<ValidatorPQKeyStore, ConsensusKeyFileError> load_consensus_key(std::string_view path) noexcept {
  SeedBuffer seed;
  if (auto refused = detail::read_protected_seed(path, seed)) {
    return as_consensus_error(*refused);
  }
  auto store = ValidatorPQKeyStore::from_seed(
      std::string_view(reinterpret_cast<const char*>(seed.bytes.data()), seed.bytes.size()));
  if (!store.has_value()) {
    return ConsensusKeyFileError::derivation_failed;
  }
  // The seed buffer is wiped by its destructor here; what survives is the signer, whose
  // own destructor wipes the expanded secret.
  return std::move(*store);
}

namespace {

// One way to put a seed on disk, whether it was generated here or handed to us. A second
// copy of this would be a second set of durability rules, and the one that got them
// wrong would be the one nobody ran.
std::variant<ConsensusPQKey, ConsensusKeyFileError> place_seed(std::string_view path, SeedBuffer& seed) noexcept {
  const std::string name(path);
  auto store = ValidatorPQKeyStore::from_seed(
      std::string_view(reinterpret_cast<const char*>(seed.bytes.data()), seed.bytes.size()));
  if (!store.has_value()) {
    return ConsensusKeyFileError::derivation_failed;
  }

  // Written under a name of its own and linked into place, so a key that is there is a
  // whole one: an interrupted write leaves the temporary behind rather than a half key
  // the node would refuse on every later start.
  //
  // The name is unique to this attempt, so a temporary left behind by an interrupted
  // run is never the name a later one wants. A fixed name would turn one crash into a
  // permanent refusal, and a name built from the process id would do the same once that
  // id came round again.
  unsigned char suffix[8]{};
  if (RAND_bytes(suffix, static_cast<int>(sizeof(suffix))) != 1) {
    return ConsensusKeyFileError::write_failed;
  }
  std::string temporary = name + ".new.";
  for (unsigned char byte : suffix) {
    static const char digits[] = "0123456789abcdef";
    temporary.push_back(digits[byte >> 4]);
    temporary.push_back(digits[byte & 15]);
  }
  {
    Descriptor fd(::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
    if (!fd.valid()) {
      return ConsensusKeyFileError::write_failed;
    }
    std::size_t written = 0;
    while (written < seed.bytes.size()) {
      const auto n = ::write(fd.get(), seed.bytes.data() + written, seed.bytes.size() - written);
      if (n < 0 && errno == EINTR) {
        continue;
      }
      if (n <= 0) {
        ::unlink(temporary.c_str());
        return ConsensusKeyFileError::write_failed;
      }
      written += static_cast<std::size_t>(n);
    }
    if (::fsync(fd.get()) != 0) {
      ::unlink(temporary.c_str());
      return ConsensusKeyFileError::write_failed;
    }
  }
  // A link, not a rename. A rename replaces whatever is at the name, so the check that
  // nothing is there and the moment the file arrives are two separate instants, and a
  // key written between them is destroyed by this one. A link refuses to create a name
  // that exists, in the same operation that creates it, so there is no interval.
  if (::link(temporary.c_str(), name.c_str()) != 0) {
    const int failure = errno;
    ::unlink(temporary.c_str());
    return failure == EEXIST ? ConsensusKeyFileError::already_exists : ConsensusKeyFileError::write_failed;
  }
  // Both names now point at the same seed. Leaving the temporary would mean a second
  // path to the secret that nothing afterwards mentions, so a key is reported as created
  // only when exactly one path to it exists. If the temporary cannot be removed the new
  // name is removed instead, which puts the directory back where it started.
  //
  // The rollback removes the entry only while it is still the one this call linked. In a
  // directory only the operator can write that is not much of a risk, but "delete
  // whatever is at this path" is a different instruction from "undo what I just did",
  // and the second is the one meant here. If it cannot be undone, both names may still
  // be there and the refusal says the key was not created, which is the truth an
  // operator can act on.
  struct stat linked{};
  const bool know_inode = ::lstat(name.c_str(), &linked) == 0;
  while (::unlink(temporary.c_str()) != 0) {
    if (errno == EINTR) {
      continue;
    }
    struct stat now{};
    if (know_inode && ::lstat(name.c_str(), &now) == 0 && now.st_dev == linked.st_dev && now.st_ino == linked.st_ino) {
      ::unlink(name.c_str());
    }
    return ConsensusKeyFileError::write_failed;
  }
  // The new name has to reach the disk, or a crash leaves the directory pointing at a
  // name that is no longer there. This is the failure the flush exists for, so it is
  // reported rather than ignored: a key that could not be made durable must not be
  // reported as created, or an operator provisions a validator that comes back without
  // its key.
  {
    Descriptor dir(::open(parent_directory(path).c_str(), O_RDONLY | O_CLOEXEC));
    if (!dir.valid() || ::fsync(dir.get()) != 0) {
      return ConsensusKeyFileError::write_failed;
    }
  }
  return store->consensus_key();
}

// A key is created, never replaced: rotating one is removing the old file deliberately.
// This answers the ordinary case before any work is done; the one that actually decides
// it is the link in `place_seed`, which cannot be raced.
ConsensusKeyFileError* nothing_is_there(std::string_view path, ConsensusKeyFileError& slot) noexcept {
  const std::string name(path);
  struct stat existing{};
  if (::lstat(name.c_str(), &existing) == 0) {
    slot = ConsensusKeyFileError::already_exists;
    return &slot;
  }
  if (!directory_is_private(path)) {
    slot = ConsensusKeyFileError::directory_writable;
    return &slot;
  }
  return nullptr;
}

}  // namespace

std::variant<ConsensusPQKey, ConsensusKeyFileError> create_consensus_key(std::string_view path) noexcept {
  ConsensusKeyFileError slot{};
  if (auto* refusal = nothing_is_there(path, slot)) {
    return *refusal;
  }
  SeedBuffer seed;
  if (RAND_priv_bytes(seed.bytes.data(), static_cast<int>(seed.bytes.size())) != 1) {
    return ConsensusKeyFileError::write_failed;
  }
  return place_seed(path, seed);
}

std::variant<ConsensusPQKey, ConsensusKeyFileError> import_consensus_key(std::string_view path,
                                                                         std::string_view provided) noexcept {
  if (provided.size() != consensus_seed_bytes) {
    return ConsensusKeyFileError::wrong_size;
  }
  ConsensusKeyFileError slot{};
  if (auto* refusal = nothing_is_there(path, slot)) {
    return *refusal;
  }
  SeedBuffer seed;
  std::memcpy(seed.bytes.data(), provided.data(), seed.bytes.size());
  return place_seed(path, seed);
}

}  // namespace tos::pq
