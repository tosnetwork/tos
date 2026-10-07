/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include "persisted.h"
#include "proof-verify.h"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
namespace {
struct Fd {
  int value{-1};
  explicit Fd(int v = -1) : value(v) {}
  ~Fd() { if (value >= 0) ::close(value); }
  Fd(const Fd &) = delete;
  Fd &operator=(const Fd &) = delete;
};
bool private_file(int fd) {
  struct stat st{};
  return fd >= 0 && ::fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == ::geteuid() &&
         (st.st_mode & 0077) == 0 && st.st_nlink == 1;
}
bool write_all(int fd, const char *data, size_t size) {
  size_t done = 0;
  while (done < size) {
    const auto n = ::write(fd, data + done, size - done);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return false;
    done += static_cast<size_t>(n);
  }
  return ::fsync(fd) == 0;
}
}
static int run_persisted(const char *directory, int initialize,
    const char *anchor, size_t anchor_size, const char *request, size_t request_size,
    int64_t local_now, const tos_proof_material *material, size_t material_count,
    char *result, size_t capacity, size_t *result_size,
    tos_proof_query_callback query, void *query_context) {
  namespace pv = tos::proofverify;
  if (result_size) *result_size = 0;
  if (!result || capacity > pv::kMaxFileBytes) return -1;
  std::memset(result, 0, capacity);
  if (!result_size || !directory || !anchor || !anchor_size || anchor_size > (1u << 20) ||
      !request || !request_size || request_size > (1u << 20) ||
      (initialize != 0 && initialize != 1)) return -1;
  try {
    auto parsed_anchor = pv::parse_anchor(td::Slice(anchor, anchor_size));
    if (parsed_anchor.is_error()) return -1;
    auto parsed = pv::parse_request(td::Slice(request, request_size));
    if (parsed.is_error() || parsed.ok().mode != pv::Mode::Live) return -1;
    Fd dir(::open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    struct stat ds{};
    if (dir.value < 0 || ::fstat(dir.value, &ds) != 0 || ds.st_uid != ::geteuid() || (ds.st_mode & 0077)) return -6;
    Fd lock(::openat(dir.value, "checkpoint.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600));
    if (!private_file(lock.value)) return -6;
    if (::flock(lock.value, LOCK_EX | LOCK_NB) != 0) return -5;
    struct Unlock { int fd; ~Unlock() { ::flock(fd, LOCK_UN); } } unlock{lock.value};
    Fd marker(::openat(dir.value, "initialized", O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
    const bool enrolled = marker.value >= 0;
    if ((!enrolled && errno != ENOENT) || (enrolled && !private_file(marker.value))) return -6;
    Fd previous(::openat(dir.value, "checkpoint.json", O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
    std::vector<char> prior;
    if (previous.value < 0) {
      if (errno != ENOENT || enrolled || !initialize) return -6;
      pv::LiveState initial; initial.anchor = parsed_anchor.ok();
      const auto text = pv::render_state(initial);
      prior.assign(text.begin(), text.end());
    } else {
      if (!enrolled || !private_file(previous.value)) return -6;
      struct stat st{};
      if (::fstat(previous.value, &st) != 0 || st.st_size <= 0 || st.st_size > (1 << 20)) return -6;
      prior.resize(static_cast<size_t>(st.st_size));
      size_t done = 0;
      while (done < prior.size()) {
        const auto n = ::read(previous.value, prior.data() + done, prior.size() - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -6;
        done += static_cast<size_t>(n);
      }
    }
    struct Collected {
      std::vector<std::vector<uint8_t>> bytes;
      std::vector<tos_proof_material> parts;
    } collected;
    if (query) {
      auto collect = [](void *context, uint32_t kind, const uint8_t *data, size_t size) -> int {
        auto &out = *static_cast<Collected *>(context);
        try {
          out.bytes.emplace_back(data, data + size);
          out.parts.push_back({kind, out.bytes.back().data(), size});
          return 0;
        } catch (...) { return -1; }
      };
      const int acquired = tos_proof_acquire(anchor, anchor_size, request, request_size, prior.data(), prior.size(),
          query, query_context, collect, &collected);
      if (acquired != 0) return -2;
      material = collected.parts.data(); material_count = collected.parts.size();
    }
    std::vector<char> answer(capacity), next(1u << 20);
    size_t answer_size = 0, next_size = 0;
    int status = tos_proof_verify_embedded(anchor, anchor_size, request, request_size, prior.data(), prior.size(),
        local_now, material, material_count, answer.data(), answer.size(), &answer_size, next.data(), next.size(), &next_size);
    if (status != 0) return status;
    if (!next_size) return -6;
    // Mark enrollment before commit: interruption can refuse recovery, never silently reset the head.
    if (!enrolled) {
      Fd created(::openat(dir.value, "initialized", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
      if (!private_file(created.value) || !write_all(created.value, "1", 1) || ::fsync(dir.value) != 0) return -6;
    }
    if (::unlinkat(dir.value, "checkpoint.tmp", 0) != 0 && errno != ENOENT) return -6;
    Fd temporary(::openat(dir.value, "checkpoint.tmp", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
    if (!private_file(temporary.value) || !write_all(temporary.value, next.data(), next_size)) return -6;
    if (::renameat(dir.value, "checkpoint.tmp", dir.value, "checkpoint.json") != 0 || ::fsync(dir.value) != 0) return -6;
    std::memcpy(result, answer.data(), answer_size); *result_size = answer_size;
    return 0;
  } catch (...) { return -4; }
}

extern "C" int tos_proof_verify_live_persisted(const char *directory, int initialize,
    const char *anchor, size_t anchor_size, const char *request, size_t request_size,
    int64_t local_now, const tos_proof_material *material, size_t material_count,
    char *result, size_t capacity, size_t *result_size) {
  return run_persisted(directory, initialize, anchor, anchor_size, request, request_size,
      local_now, material, material_count, result, capacity, result_size, nullptr, nullptr);
}
extern "C" int tos_proof_acquire_verify_live_persisted(const char *directory, int initialize,
    const char *anchor, size_t anchor_size, const char *request, size_t request_size,
    int64_t local_now, tos_proof_query_callback query, void *query_context,
    char *result, size_t capacity, size_t *result_size) {
  if (!query) {
    if (result_size) *result_size = 0;
    if (result && capacity <= tos::proofverify::kMaxFileBytes) std::memset(result, 0, capacity);
    return -1;
  }
  return run_persisted(directory, initialize, anchor, anchor_size, request, request_size,
      local_now, nullptr, 0, result, capacity, result_size, query, query_context);
}
