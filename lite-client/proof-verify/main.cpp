/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// tos-proof-verify: authenticate a masterchain block from a locally provisioned
// anchor and return proven configuration, account state and get-method results
// as one JSON object on stdout. Exit status 0 means verified; anything else
// means refused, and stdout then carries only a refusal object.
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <string>
#include <sys/file.h>
#include <unistd.h>

#include "td/utils/logging.h"

#include "material.h"
#include "proof-verify.h"

namespace {

using namespace tos::proofverify;

constexpr int kExitVerified = 0;
constexpr int kExitRefused = 1;
constexpr int kExitUsage = 2;

int emit(const std::string& json, int code) {
  std::fwrite(json.data(), 1, json.size(), stdout);
  std::fputc('\n', stdout);
  if (std::fflush(stdout) != 0) {
    return kExitRefused;
  }
  return code;
}

int refuse(td::Slice reason, int code = kExitRefused) {
  return emit(render_refusal(reason), code);
}

constexpr char usage[] =
    "usage: tos-proof-verify verify --anchor FILE --request FILE "
    "(--liteserver FILE | --material DIR) [--state FILE] [--save-material DIR] "
    "[--min-interval-ms N] [--timeout-seconds N]\n"
    "       tos-proof-verify anchor --zerostate FILE";

struct Options {
  std::string anchor;
  std::string request;
  std::string liteserver;
  std::string material;
  std::string state;
  std::string save_material;
  long min_interval_ms{200};
  long timeout_seconds{20};
};

td::Result<long> parse_bounded(const char* text, long low, long high) {
  char* end = nullptr;
  errno = 0;
  long value = std::strtol(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || value < low || value > high) {
    return td::Status::Error("numeric option is out of range");
  }
  return value;
}

td::Result<Options> parse_options(int argc, char** argv) {
  Options options;
  for (int i = 2; i < argc; ++i) {
    std::string flag = argv[i];
    if (i + 1 >= argc) {
      return td::Status::Error(PSLICE() << "option " << flag << " needs a value");
    }
    const char* value = argv[++i];
    if (flag == "--anchor") {
      options.anchor = value;
    } else if (flag == "--request") {
      options.request = value;
    } else if (flag == "--liteserver") {
      options.liteserver = value;
    } else if (flag == "--material") {
      options.material = value;
    } else if (flag == "--state") {
      options.state = value;
    } else if (flag == "--save-material") {
      options.save_material = value;
    } else if (flag == "--min-interval-ms") {
      TRY_RESULT_ASSIGN(options.min_interval_ms, parse_bounded(value, 0, 60000));
    } else if (flag == "--timeout-seconds") {
      TRY_RESULT_ASSIGN(options.timeout_seconds, parse_bounded(value, 1, 600));
    } else {
      return td::Status::Error(PSLICE() << "unknown option " << flag);
    }
  }
  if (options.anchor.empty() || options.request.empty()) {
    return td::Status::Error("--anchor and --request are required");
  }
  if (options.liteserver.empty() == options.material.empty()) {
    return td::Status::Error("exactly one of --liteserver and --material is required");
  }
  if (!options.save_material.empty() && options.liteserver.empty()) {
    return td::Status::Error("--save-material only applies to fetched material");
  }
  return options;
}

// Holds an exclusive lock on the live state record for the whole run so two
// verifiers cannot interleave reads and commits.
class StateLock {
 public:
  ~StateLock() {
    if (fd_ >= 0) {
      ::close(fd_);
    }
  }
  td::Status acquire(const std::string& path) {
    fd_ = ::open((path + ".lock").c_str(), O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd_ < 0) {
      return td::Status::PosixError(errno, "cannot open live state lock");
    }
    if (::flock(fd_, LOCK_EX | LOCK_NB) != 0) {
      return td::Status::Error("live state record is in use by another verifier");
    }
    return td::Status::OK();
  }

 private:
  int fd_{-1};
};

td::Result<std::optional<LiveState>> load_state(const std::string& path, const Anchor& anchor) {
  if (::access(path.c_str(), F_OK) != 0) {
    if (errno != ENOENT) {
      return td::Status::PosixError(errno, "cannot inspect live state record");
    }
    // First live run for this anchor: nothing has been authenticated yet.
    LiveState state;
    state.anchor = anchor;
    return std::optional<LiveState>{state};
  }
  TRY_RESULT(text, read_bounded_file(path, 1u << 20));
  TRY_RESULT(state, parse_state(text));
  return std::optional<LiveState>{state};
}

td::Status sync_directory_of(const std::string& path) {
  const auto slash = path.rfind('/');
  const std::string directory = slash == std::string::npos ? "." : slash == 0 ? "/" : path.substr(0, slash);
  int fd = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0) {
    return td::Status::PosixError(errno, "cannot open live state directory");
  }
  const bool synced = ::fsync(fd) == 0;
  const int sync_errno = errno;
  const bool closed = ::close(fd) == 0;
  if (!synced) {
    return td::Status::PosixError(sync_errno, "cannot sync live state directory");
  }
  if (!closed) {
    return td::Status::Error("cannot close live state directory");
  }
  return td::Status::OK();
}

td::Status commit_state(const std::string& path, const LiveState& state) {
  const auto temporary = path + ".tmp";
  ::unlink(temporary.c_str());
  int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) {
    return td::Status::PosixError(errno, "cannot create live state record");
  }
  auto text = render_state(state) + "\n";
  std::size_t done = 0;
  while (done < text.size()) {
    auto written = ::write(fd, text.data() + done, text.size() - done);
    if (written < 0 && errno == EINTR) {
      continue;
    }
    if (written <= 0) {
      ::close(fd);
      return td::Status::Error("cannot write live state record");
    }
    done += static_cast<std::size_t>(written);
  }
  const bool synced = ::fsync(fd) == 0;
  const bool closed = ::close(fd) == 0;
  if (!synced || !closed) {
    return td::Status::Error("cannot flush live state record");
  }
  if (::rename(temporary.c_str(), path.c_str()) != 0) {
    return td::Status::PosixError(errno, "cannot commit live state record");
  }
  // The replacement is durable only once the directory entry is: without this
  // a power loss can bring back the previous head and reopen a rollback.
  return sync_directory_of(path);
}

int run_anchor(int argc, char** argv) {
  if (argc != 4 || std::string(argv[2]) != "--zerostate") {
    return refuse(usage, kExitUsage);
  }
  auto bytes = read_bounded_file(argv[3], kMaxFileBytes);
  if (bytes.is_error()) {
    return refuse(bytes.error().message());
  }
  auto anchor = anchor_from_zerostate(bytes.ok());
  if (anchor.is_error()) {
    return refuse(anchor.error().message());
  }
  return emit(render_anchor(anchor.ok()), kExitVerified);
}

int run_verify(int argc, char** argv) {
  auto parsed = parse_options(argc, argv);
  if (parsed.is_error()) {
    return refuse(PSLICE() << parsed.error().message() << "; " << usage, kExitUsage);
  }
  auto options = parsed.move_as_ok();
  auto anchor_text = read_bounded_file(options.anchor, 1u << 16);
  if (anchor_text.is_error()) {
    return refuse(anchor_text.error().message());
  }
  auto anchor = parse_anchor(anchor_text.ok());
  if (anchor.is_error()) {
    return refuse(PSLICE() << "anchor: " << anchor.error().message());
  }
  auto request_text = read_bounded_file(options.request, 1u << 20);
  if (request_text.is_error()) {
    return refuse(request_text.error().message());
  }
  auto request = parse_request(request_text.ok());
  if (request.is_error()) {
    return refuse(PSLICE() << "request: " << request.error().message());
  }
  const bool live = request.ok().mode == Mode::Live;
  if (live == options.state.empty()) {
    return refuse("live mode requires --state and historical mode refuses it", kExitUsage);
  }
  StateLock lock;
  std::optional<LiveState> state;
  if (live) {
    auto locked = lock.acquire(options.state);
    if (locked.is_error()) {
      return refuse(locked.message());
    }
    auto loaded = load_state(options.state, anchor.ok());
    if (loaded.is_error()) {
      return refuse(PSLICE() << "live state: " << loaded.error().message());
    }
    state = loaded.move_as_ok();
  }

  Material material;
  if (!options.liteserver.empty()) {
    FetchOptions fetch_options;
    fetch_options.min_interval_seconds = static_cast<double>(options.min_interval_ms) / 1000.0;
    fetch_options.timeout_seconds = static_cast<double>(options.timeout_seconds);
    auto transport = connect_liteserver(options.liteserver, fetch_options);
    if (transport.is_error()) {
      return refuse(transport.error().message());
    }
    auto fetched = fetch_material(*transport.ok(), anchor.ok(), request.ok(), state);
    if (fetched.is_error()) {
      return refuse(PSLICE() << "acquisition: " << fetched.error().message());
    }
    material = fetched.move_as_ok();
    if (!options.save_material.empty()) {
      auto saved = write_material(options.save_material, material);
      if (saved.is_error()) {
        return refuse(saved.message());
      }
    }
  } else {
    auto read = read_material(options.material);
    if (read.is_error()) {
      return refuse(read.error().message());
    }
    material = read.move_as_ok();
  }

  Policy policy;
  policy.now = static_cast<std::int64_t>(std::time(nullptr));
  auto verified = verify(anchor.ok(), request.ok(), request_text.ok(), material, state, policy);
  if (verified.is_error()) {
    return refuse(verified.error().message());
  }
  if (live) {
    if (!verified.ok().next_state) {
      return refuse("live verification produced no state to commit");
    }
    auto committed = commit_state(options.state, *verified.ok().next_state);
    if (committed.is_error()) {
      return refuse(committed.message());
    }
  }
  return emit(render_verified(verified.ok()), kExitVerified);
}

}  // namespace

int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(FATAL));
  if (argc < 2) {
    return refuse(usage, kExitUsage);
  }
  std::string command = argv[1];
  if (command == "verify") {
    return run_verify(argc, argv);
  }
  if (command == "anchor") {
    return run_anchor(argc, argv);
  }
  return refuse(usage, kExitUsage);
}
