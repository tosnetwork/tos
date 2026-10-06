/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <unistd.h>
#include <variant>

#include "auto/tl/tos_api.h"
#include "auto/tl/tos_api_json.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/common.h"
#include "tl/tl_json.h"

#include "consensus-key-file.h"
#include "consensus-node-config.h"
#include "seed-file.h"

namespace tos::pq {
namespace {

using detail::Descriptor;
using detail::parent_directory;

// A node configuration is a few kilobytes to a few megabytes. Anything far beyond that is
// not one, and reading it whole would be the wrong response.
constexpr off_t config_size_limit = 64 << 20;

int nibble(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

std::string hex(const td::Bits256& value) {
  static const char digits[] = "0123456789abcdef";
  std::string out;
  for (const unsigned char byte : value.as_array()) {
    out.push_back(digits[byte >> 4]);
    out.push_back(digits[byte & 15]);
  }
  return out;
}

std::string errno_text(const char* what) {
  return std::string(what) + ": " + std::strerror(errno);
}

bool read_whole(int fd, off_t size, std::string& out) {
  out.assign(static_cast<std::size_t>(size), '\0');
  std::size_t done = 0;
  while (done < out.size()) {
    const auto n = ::read(fd, out.data() + done, out.size() - done);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return false;
    }
    done += static_cast<std::size_t>(n);
  }
  // The file must end where fstat said it does. A longer file is one that changed while
  // it was read, and a prefix of it is not a configuration.
  char extra = 0;
  for (;;) {
    const auto n = ::read(fd, &extra, 1);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    return n == 0;
  }
}

bool write_whole(int fd, const std::string& data) {
  std::size_t done = 0;
  while (done < data.size()) {
    const auto n = ::write(fd, data.data() + done, data.size() - done);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return false;
    }
    done += static_cast<std::size_t>(n);
  }
  return true;
}

// A running engine holds its cell database open under an exclusive lock. If something
// holds it, the engine is up, and it would write its own configuration over this edit
// the next time anything changed.
bool database_is_held(const std::string& db_root, std::string& why) {
  const std::string lock_path = db_root + "/celldb/LOCK";
  Descriptor fd(::open(lock_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  if (!fd.valid()) {
    if (errno == ENOENT) {
      return false;  // no database yet: the generate step does not create one
    }
    why = errno_text(("cannot check whether a node holds " + lock_path).c_str());
    return true;
  }
  struct flock probe{};
  probe.l_type = F_WRLCK;
  probe.l_whence = SEEK_SET;
  probe.l_start = 0;
  probe.l_len = 0;
  if (::fcntl(fd.get(), F_GETLK, &probe) != 0) {
    why = errno_text(("cannot check whether a node holds " + lock_path).c_str());
    return true;
  }
  if (probe.l_type != F_UNLCK) {
    why = "a running node holds " + lock_path + " (pid " + std::to_string(probe.l_pid) +
          "); stop it before changing its configuration";
    return true;
  }
  return false;
}

std::string encode(const tos::tos_api::engine_validator_config& config) {
  // Exactly what the engine writes: the same serializer, pretty-printed as it does.
  return td::json_encode<std::string>(td::ToJson(config), true);
}

bool decode(std::string text, tos::tos_api::engine_validator_config& config, std::string& why) {
  auto json = td::json_decode(td::MutableSlice(text));
  if (json.is_error()) {
    why = "the configuration is not JSON: " + json.error().message().str();
    return false;
  }
  auto value = json.move_as_ok();
  if (value.type() != td::JsonValue::Type::Object) {
    why = "the configuration is not a JSON object";
    return false;
  }
  auto status = tos::tos_api::from_json(config, value.get_object());
  if (status.is_error()) {
    why = "the configuration does not fit the engine's schema: " + status.message().str();
    return false;
  }
  return true;
}

bool same_binding(const tos::tos_api::engine_validator_pqConsensus& held, const td::Bits256& id,
                  const std::string& file) {
  return held.validator_id_ == id && held.consensus_key_file_ == file;
}

}  // namespace

bool parse_validator_id(std::string_view text, std::array<std::uint8_t, 32>& out, std::string& why) {
  if (text.size() == 67 && text.substr(0, 3) == "-1:") {
    text.remove_prefix(3);
  } else if (text.find(':') != std::string_view::npos) {
    why = "a validator id is a masterchain controller: 64 hex digits or -1:<64 hex digits>";
    return false;
  }
  if (text.size() != 64) {
    why = "a validator id is 64 hexadecimal digits";
    return false;
  }
  bool zero = true;
  for (std::size_t i = 0; i < out.size(); i++) {
    const int hi = nibble(text[2 * i]);
    const int lo = nibble(text[2 * i + 1]);
    if (hi < 0 || lo < 0) {
      why = "a validator id is 64 hexadecimal digits";
      return false;
    }
    out[i] = static_cast<std::uint8_t>(hi * 16 + lo);
    zero = zero && out[i] == 0;
  }
  if (zero) {
    why = "the validator id is zero; the node refuses to start with it";
    return false;
  }
  return true;
}

bool bind_node_consensus_key(const NodeConsensusBinding& binding, NodeConsensusBindingResult& result,
                             std::string& why) {
  // The node runs with / as its working directory under a service manager, so a relative
  // path would name a different file there than here.
  if (binding.key_file.empty() || binding.key_file.front() != '/') {
    why = "the key file must be given as an absolute path";
    return false;
  }

  // The key is checked under the node's own rules, by the node's own loader, as the user
  // running this. That is why this has to run as the node's service account: a key the
  // node cannot read would be accepted here and refused at start.
  auto loaded = load_consensus_key(binding.key_file);
  if (std::holds_alternative<ConsensusKeyFileError>(loaded)) {
    why = binding.key_file + ": " + describe(std::get<ConsensusKeyFileError>(loaded));
    return false;
  }
  result.key_id = std::get<ValidatorPQKeyStore>(loaded).consensus_key().key_id;

  const std::string& path = binding.config_path;
  const std::string directory = parent_directory(path);
  if (database_is_held(directory, why)) {
    return false;
  }

  struct stat before{};
  std::string original;
  {
    Descriptor fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (!fd.valid()) {
      why = errno_text((path + ": cannot open the configuration (a symbolic link is refused)").c_str());
      return false;
    }
    if (::fstat(fd.get(), &before) != 0) {
      why = errno_text(path.c_str());
      return false;
    }
    if (!S_ISREG(before.st_mode)) {
      why = path + ": the configuration is not a regular file";
      return false;
    }
    // The engine rewrites this file as the user it runs as. A file that user does not own
    // would come back owned by whoever ran this, and the engine could not replace it.
    if (before.st_uid != ::geteuid()) {
      why = path + ": the configuration is owned by another user; run this as the node's service account";
      return false;
    }
    if (before.st_size <= 0 || before.st_size > config_size_limit) {
      why = path + ": the configuration is empty or too large to be one";
      return false;
    }
    if (!read_whole(fd.get(), before.st_size, original)) {
      why = path + ": the configuration could not be read to its end, or changed while it was read";
      return false;
    }
  }

  tos::tos_api::engine_validator_config config;
  if (!decode(original, config, why)) {
    why = path + ": " + why;
    return false;
  }

  td::Bits256 id;
  std::memcpy(id.data(), binding.validator_id.data(), binding.validator_id.size());

  if (config.extraconfig_ && config.extraconfig_->pq_consensus_) {
    const auto& held = *config.extraconfig_->pq_consensus_;
    if (same_binding(held, id, binding.key_file)) {
      result.changed = false;
      return true;
    }
    if (!binding.replace) {
      why = path + ": the node is already bound to validator " + hex(held.validator_id_) + " with key file " +
            held.consensus_key_file_ + "; pass --replace to change it deliberately";
      return false;
    }
  }

  if (!config.extraconfig_) {
    // An absent extra configuration means the engine's defaults, and the one default that
    // is not the type's own is that the state serializer runs. Creating the object with
    // the type's default would turn it off.
    config.extraconfig_ = tos::create_tl_object<tos::tos_api::engine_validator_extraConfig>();
    config.extraconfig_->state_serializer_enabled_ = true;
  }
  config.extraconfig_->pq_consensus_ =
      tos::create_tl_object<tos::tos_api::engine_validator_pqConsensus>(id, binding.key_file);

  const std::string updated = encode(config);

  unsigned char suffix[8]{};
  if (RAND_bytes(suffix, static_cast<int>(sizeof(suffix))) != 1) {
    why = "no random name for the temporary file";
    return false;
  }
  std::string temporary = path + ".pq-bind.";
  for (unsigned char byte : suffix) {
    static const char digits[] = "0123456789abcdef";
    temporary.push_back(digits[byte >> 4]);
    temporary.push_back(digits[byte & 15]);
  }
  {
    Descriptor fd(::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
    if (!fd.valid()) {
      why = errno_text((temporary + ": cannot create").c_str());
      return false;
    }
    // The new file keeps the old one's permissions, whatever the umask of this shell.
    if (::fchmod(fd.get(), before.st_mode & 07777) != 0 || !write_whole(fd.get(), updated) || ::fsync(fd.get()) != 0) {
      why = errno_text((temporary + ": cannot write").c_str());
      ::unlink(temporary.c_str());
      return false;
    }
  }

  // The file this replaces must still be the one that was read. Anything else changed it
  // in the meantime, and replacing it would lose that change.
  struct stat now{};
  if (::lstat(path.c_str(), &now) != 0 || now.st_dev != before.st_dev || now.st_ino != before.st_ino ||
      now.st_size != before.st_size || now.st_mtim.tv_sec != before.st_mtim.tv_sec ||
      now.st_mtim.tv_nsec != before.st_mtim.tv_nsec) {
    ::unlink(temporary.c_str());
    why = path + ": the configuration changed while it was being edited; nothing was written";
    return false;
  }
  if (::rename(temporary.c_str(), path.c_str()) != 0) {
    why = errno_text((path + ": cannot replace").c_str());
    ::unlink(temporary.c_str());
    return false;
  }
  Descriptor dir(::open(directory.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY));
  if (!dir.valid() || ::fsync(dir.get()) != 0) {
    why =
        errno_text((directory + ": the new configuration is in place but its directory could not be flushed").c_str());
    return false;
  }
  result.changed = true;
  return true;
}

}  // namespace tos::pq
