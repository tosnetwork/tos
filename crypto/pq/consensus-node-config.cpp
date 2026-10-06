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

std::string errno_text(const std::string& what) {
  return what + ": " + std::strerror(errno);
}

// The modification time to the nanosecond. The field is named differently on Linux and
// on macOS; the value is the same.
std::int64_t mtime_ns(const struct stat& st) {
#if defined(__APPLE__)
  return static_cast<std::int64_t>(st.st_mtimespec.tv_sec) * 1000000000 + st.st_mtimespec.tv_nsec;
#else
  return static_cast<std::int64_t>(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec;
#endif
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

// Take the configuration lock the engine holds for as long as it runs. Held, it means a
// running node or another binder; taken, it keeps the engine from starting until this
// edit is in place, because the engine takes it before it reads its configuration.
// Returns the descriptor holding the lock, or -1 with the reason in `why`.
int take_config_lock(const std::string& db_root, std::string& why) {
  const std::string path = db_root + "/" + node_config_lock_name;
  const int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0) {
    why = errno_text(path + ": cannot open the configuration lock");
    return -1;
  }
  struct flock lock{};
  lock.l_type = F_WRLCK;
  lock.l_whence = SEEK_SET;
  lock.l_start = 0;
  lock.l_len = 0;
  if (::fcntl(fd, F_SETLK, &lock) != 0) {
    if (errno == EAGAIN || errno == EACCES) {
      why = path + " is held by a running node or another bind-node; stop the node before changing its configuration";
    } else {
      why = errno_text(path + ": cannot lock");
    }
    ::close(fd);
    return -1;
  }
  return fd;
}

// The cell database's own lock, taken as well when the database exists: a running engine
// holds it exclusively, and holding it here keeps the database from being opened until
// the edit is done. It is a second guard, not the proof: the configuration lock is the
// one the engine takes before it reads anything, and an absent cell database lock (a
// node never started, or a pathname someone removed) proves nothing either way.
// Returns the held descriptor, -1 when there is no cell database lock file, or -2 with
// the reason in `why` when it cannot be taken.
int take_cell_database_lock(const std::string& db_root, std::string& why) {
  const std::string lock_path = db_root + "/celldb/LOCK";
  const int fd = ::open(lock_path.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) {
    if (errno == ENOENT) {
      return -1;
    }
    why = errno_text("cannot lock " + lock_path);
    return -2;
  }
  struct flock lock{};
  lock.l_type = F_WRLCK;
  lock.l_whence = SEEK_SET;
  lock.l_start = 0;
  lock.l_len = 0;
  if (::fcntl(fd, F_SETLK, &lock) != 0) {
    if (errno == EAGAIN || errno == EACCES) {
      why = "a running node holds " + lock_path + "; stop it before changing its configuration";
    } else {
      why = errno_text("cannot lock " + lock_path);
    }
    ::close(fd);
    return -2;
  }
  return fd;
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

// Whether everything `original` says is still said by `rewritten`, and if not, where it
// first stops. Fields the encoder adds with their default values are not a loss; a field
// it drops, or a value it changes, is. An integer the engine accepts either as a number
// or as a string is the same value in both forms.
bool says_everything(const td::JsonValue& original, const td::JsonValue& rewritten, const std::string& at,
                     std::string& lost) {
  using Type = td::JsonValue::Type;
  const auto scalar = [](const td::JsonValue& v) { return v.type() == Type::Number || v.type() == Type::String; };
  if (scalar(original) && scalar(rewritten)) {
    const td::Slice a = original.type() == Type::Number ? td::Slice(original.get_number()) : original.get_string();
    const td::Slice b = rewritten.type() == Type::Number ? td::Slice(rewritten.get_number()) : rewritten.get_string();
    if (a == b) {
      return true;
    }
    lost = at;
    return false;
  }
  if (original.type() != rewritten.type()) {
    lost = at;
    return false;
  }
  switch (original.type()) {
    case Type::Null:
      return true;
    case Type::Boolean:
      if (original.get_boolean() == rewritten.get_boolean()) {
        return true;
      }
      lost = at;
      return false;
    case Type::Array: {
      const auto& a = original.get_array();
      const auto& b = rewritten.get_array();
      if (a.size() != b.size()) {
        lost = at;
        return false;
      }
      for (std::size_t i = 0; i < a.size(); i++) {
        if (!says_everything(a[i], b[i], at + "[" + std::to_string(i) + "]", lost)) {
          return false;
        }
      }
      return true;
    }
    case Type::Object: {
      for (const auto& [name, value] : original.get_object().field_values_) {
        const td::JsonValue* match = nullptr;
        for (const auto& [other_name, other_value] : rewritten.get_object().field_values_) {
          if (other_name == name) {
            match = &other_value;
            break;
          }
        }
        const std::string here = at + "." + name.str();
        if (match == nullptr) {
          lost = here;
          return false;
        }
        if (!says_everything(value, *match, here, lost)) {
          return false;
        }
      }
      return true;
    }
    case Type::Number:
    case Type::String:
      break;  // handled above
  }
  lost = at;
  return false;
}

// The engine rewrites its configuration through this same schema, so anything outside it
// would be gone after the engine's next write anyway. Dropping it here, silently, would
// make this command the one that lost it; refusing names it while the operator can still
// move it somewhere that is kept.
bool schema_keeps_everything(const std::string& original, const tos::tos_api::engine_validator_config& config,
                             std::string& why) {
  std::string original_copy = original;
  std::string rewritten = encode(config);
  auto a = td::json_decode(td::MutableSlice(original_copy));
  auto b = td::json_decode(td::MutableSlice(rewritten));
  if (a.is_error() || b.is_error()) {
    why = "the configuration could not be compared with its rewritten form";
    return false;
  }
  std::string lost;
  if (!says_everything(a.ok(), b.ok(), "$", lost)) {
    why = "the configuration has content the engine's schema does not keep, at " + lost +
          "; the engine would drop it on its next write. Remove it or move it elsewhere first";
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

NodeBindingOutcome bind_node_consensus_key(const NodeConsensusBinding& binding, NodeConsensusBindingResult& result,
                                           std::string& why) {
  // The node runs with / as its working directory under a service manager, so a relative
  // path would name a different file there than here.
  if (binding.key_file.empty() || binding.key_file.front() != '/') {
    why = "the key file must be given as an absolute path";
    return NodeBindingOutcome::refused;
  }

  // The key is checked under the node's own rules, by the node's own loader, as the user
  // running this. That is why this has to run as the node's service account: a key the
  // node cannot read would be accepted here and refused at start.
  auto loaded = load_consensus_key(binding.key_file);
  if (std::holds_alternative<ConsensusKeyFileError>(loaded)) {
    why = binding.key_file + ": " + describe(std::get<ConsensusKeyFileError>(loaded));
    return NodeBindingOutcome::refused;
  }
  result.key_id = std::get<ValidatorPQKeyStore>(loaded).consensus_key().key_id;

  // The engine reads <db>/config.json and nothing else, so the database root is what is
  // named, and the configuration is found where the engine finds it.
  const std::string& db_root = binding.db_root;
  {
    struct stat root{};
    if (db_root.empty() || ::stat(db_root.c_str(), &root) != 0 || !S_ISDIR(root.st_mode)) {
      why = db_root + ": not a database directory";
      return NodeBindingOutcome::refused;
    }
  }
  const std::string path = db_root + "/config.json";
  result.config_path = path;

  // Held from here until the new configuration is in place: no engine starts, and no
  // other binder reads, until then.
  Descriptor config_lock(take_config_lock(db_root, why));
  if (!config_lock.valid()) {
    return NodeBindingOutcome::refused;
  }
  const int cell_lock_fd = take_cell_database_lock(db_root, why);
  if (cell_lock_fd == -2) {
    return NodeBindingOutcome::refused;
  }
  Descriptor cell_lock(cell_lock_fd);  // -1 holds nothing

  // The engine writes config.json.tmp and renames it; it reads the temporary file in place
  // of a missing config.json. One left behind is an interrupted engine write that may be
  // newer than config.json, and which of the two is right is the operator's call.
  {
    const std::string temporary = path + ".tmp";
    struct stat leftover{};
    if (::lstat(temporary.c_str(), &leftover) == 0) {
      why = temporary + " exists: an interrupted engine write. Compare it with " + path +
            ", keep the right one as config.json, remove the other, then run this again";
      return NodeBindingOutcome::refused;
    }
    if (errno != ENOENT) {
      why = errno_text("cannot check " + temporary);
      return NodeBindingOutcome::refused;
    }
  }

  struct stat before{};
  std::string original;
  {
    // Opened without blocking, so a FIFO at this name is refused rather than waited on.
    Descriptor fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (!fd.valid()) {
      why = errno_text(path + ": cannot open the configuration (a symbolic link is refused)");
      return NodeBindingOutcome::refused;
    }
    if (::fstat(fd.get(), &before) != 0) {
      why = errno_text(path);
      return NodeBindingOutcome::refused;
    }
    if (!S_ISREG(before.st_mode)) {
      why = path + ": the configuration is not a regular file";
      return NodeBindingOutcome::refused;
    }
    const int flags = ::fcntl(fd.get(), F_GETFL);
    if (flags < 0 || ::fcntl(fd.get(), F_SETFL, flags & ~O_NONBLOCK) != 0) {
      why = errno_text(path);
      return NodeBindingOutcome::refused;
    }
    // The engine rewrites this file as the user it runs as. A file that user does not own
    // would come back owned by whoever ran this, and the engine could not replace it.
    if (before.st_uid != ::geteuid()) {
      why = path + ": the configuration is owned by another user; run this as the node's service account";
      return NodeBindingOutcome::refused;
    }
    if (before.st_size <= 0 || before.st_size > config_size_limit) {
      why = path + ": the configuration is empty or too large to be one";
      return NodeBindingOutcome::refused;
    }
    if (!read_whole(fd.get(), before.st_size, original)) {
      why = path + ": the configuration could not be read to its end, or changed while it was read";
      return NodeBindingOutcome::refused;
    }
  }

  tos::tos_api::engine_validator_config config;
  if (!decode(original, config, why)) {
    why = path + ": " + why;
    return NodeBindingOutcome::refused;
  }
  if (!schema_keeps_everything(original, config, why)) {
    why = path + ": " + why;
    return NodeBindingOutcome::refused;
  }

  td::Bits256 id;
  std::memcpy(id.data(), binding.validator_id.data(), binding.validator_id.size());

  if (config.extraconfig_ && config.extraconfig_->pq_consensus_) {
    const auto& held = *config.extraconfig_->pq_consensus_;
    if (same_binding(held, id, binding.key_file)) {
      return NodeBindingOutcome::unchanged;
    }
    if (!binding.replace) {
      why = path + ": the node is already bound to validator " + hex(held.validator_id_) + " with key file " +
            held.consensus_key_file_ + "; pass --replace to change it deliberately";
      return NodeBindingOutcome::refused;
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
    return NodeBindingOutcome::refused;
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
      why = errno_text(temporary + ": cannot create");
      return NodeBindingOutcome::refused;
    }
    // The new file keeps the old one's group and permissions, whatever the umask of this
    // shell and the group of this user. A group this user cannot give it is a refusal,
    // not a quiet change of who may read the configuration.
    if (::fchown(fd.get(), static_cast<uid_t>(-1), before.st_gid) != 0) {
      why = errno_text(path + ": cannot keep the configuration's group " + std::to_string(before.st_gid));
      ::unlink(temporary.c_str());
      return NodeBindingOutcome::refused;
    }
    if (::fchmod(fd.get(), before.st_mode & 07777) != 0 || !write_whole(fd.get(), updated) || ::fsync(fd.get()) != 0) {
      why = errno_text(temporary + ": cannot write");
      ::unlink(temporary.c_str());
      return NodeBindingOutcome::refused;
    }
  }

  // The file this replaces must still be the one that was read. The lock keeps the engine
  // and other binders out; this catches anything else that wrote it in the meantime.
  struct stat now{};
  if (::lstat(path.c_str(), &now) != 0 || now.st_dev != before.st_dev || now.st_ino != before.st_ino ||
      now.st_size != before.st_size || mtime_ns(now) != mtime_ns(before)) {
    ::unlink(temporary.c_str());
    why = path + ": the configuration changed while it was being edited; nothing was written";
    return NodeBindingOutcome::refused;
  }
  if (::rename(temporary.c_str(), path.c_str()) != 0) {
    why = errno_text(path + ": cannot replace");
    ::unlink(temporary.c_str());
    return NodeBindingOutcome::refused;
  }
  // From here the binding is in place. What remains is making the rename itself survive a
  // crash; failing that is not a refusal, and is reported as what it is.
  Descriptor dir(::open(db_root.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY));
  if (!dir.valid() || ::fsync(dir.get()) != 0) {
    why = errno_text(db_root + ": the directory could not be flushed");
    return NodeBindingOutcome::applied_not_durable;
  }
  return NodeBindingOutcome::applied;
}

}  // namespace tos::pq
