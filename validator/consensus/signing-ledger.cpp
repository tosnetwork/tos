/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "td/utils/crypto.h"
#include "td/utils/logging.h"
#include "td/utils/misc.h"
#include "td/utils/port/Clocks.h"
#include "tos/tos-shard.h"

#include "signing-ledger.h"

namespace tos::validator::consensus::signing {

namespace {

constexpr unsigned char kRecordTag = 0xD1;
constexpr char kHeaderMagic[8] = {'T', 'O', 'S', 'S', 'L', 'G', '0', '2'};
constexpr const char* kHeaderName = "ledger";
constexpr const char* kLogPrefix = "log.";

void put_u32(std::string& out, std::uint32_t value) {
  for (int i = 0; i < 4; ++i) {
    out.push_back(static_cast<char>((value >> (8 * i)) & 0xff));
  }
}

void put_u64(std::string& out, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<char>((value >> (8 * i)) & 0xff));
  }
}

void put_bits(std::string& out, const td::Bits256& value) {
  out.append(reinterpret_cast<const char*>(value.data()), 32);
}

// A bounded reader: every read checks that the bytes are there, so nothing is decoded or
// allocated from a length the input has not been shown to contain.
class Reader {
 public:
  explicit Reader(td::Slice bytes) : bytes_(bytes) {
  }
  bool u8(std::uint8_t& value) {
    if (pos_ + 1 > bytes_.size()) {
      return false;
    }
    value = static_cast<std::uint8_t>(bytes_[pos_]);
    pos_ += 1;
    return true;
  }
  bool u32(std::uint32_t& value) {
    if (pos_ + 4 > bytes_.size()) {
      return false;
    }
    value = 0;
    for (int i = 0; i < 4; ++i) {
      value |= static_cast<std::uint32_t>(static_cast<unsigned char>(bytes_[pos_ + i])) << (8 * i);
    }
    pos_ += 4;
    return true;
  }
  bool u64(std::uint64_t& value) {
    if (pos_ + 8 > bytes_.size()) {
      return false;
    }
    value = 0;
    for (int i = 0; i < 8; ++i) {
      value |= static_cast<std::uint64_t>(static_cast<unsigned char>(bytes_[pos_ + i])) << (8 * i);
    }
    pos_ += 8;
    return true;
  }
  bool bits(td::Bits256& value) {
    if (pos_ + 32 > bytes_.size()) {
      return false;
    }
    std::memcpy(value.data(), bytes_.data() + pos_, 32);
    pos_ += 32;
    return true;
  }
  std::size_t position() const {
    return pos_;
  }
  std::size_t remaining() const {
    return bytes_.size() - pos_;
  }

 private:
  td::Slice bytes_;
  std::size_t pos_ = 0;
};

void put_binding(std::string& out, const Binding& binding) {
  put_u64(out, binding.ino);
  put_u64(out, static_cast<std::uint64_t>(binding.btime_sec));
  put_u32(out, binding.btime_nsec);
}

bool get_binding(Reader& in, Binding& binding) {
  std::uint64_t ino = 0;
  std::uint64_t sec = 0;
  std::uint32_t nsec = 0;
  if (!in.u64(ino) || !in.u64(sec) || !in.u32(nsec)) {
    return false;
  }
  binding.ino = ino;
  binding.btime_sec = static_cast<std::int64_t>(sec);
  binding.btime_nsec = nsec;
  return true;
}

std::array<unsigned char, 16> chain_step(const std::array<unsigned char, 16>& previous, td::Slice body) {
  std::string input(reinterpret_cast<const char*>(previous.data()), previous.size());
  input.append(body.data(), body.size());
  unsigned char digest[32];
  td::sha256(input, td::MutableSlice(reinterpret_cast<char*>(digest), 32));
  std::array<unsigned char, 16> next{};
  std::memcpy(next.data(), digest, next.size());
  return next;
}

bool valid_kind(std::uint8_t kind) {
  return kind >= static_cast<std::uint8_t>(DecisionKind::Notarize) &&
         kind <= static_cast<std::uint8_t>(DecisionKind::LeaderWindow);
}

bool has_candidate(DecisionKind kind) {
  return kind == DecisionKind::Notarize || kind == DecisionKind::Finalize;
}

std::string errno_text() {
  return std::string(std::strerror(errno));
}

bool file_exists(const std::string& path) {
  struct stat st{};
  return ::lstat(path.c_str(), &st) == 0;
}

// Whether `dir` holds any log file.
bool has_log_files(const std::string& dir) {
  DIR* handle = ::opendir(dir.c_str());
  if (handle == nullptr) {
    return false;
  }
  bool found = false;
  while (auto* entry = ::readdir(handle)) {
    if (std::strncmp(entry->d_name, kLogPrefix, std::strlen(kLogPrefix)) == 0) {
      found = true;
      break;
    }
  }
  ::closedir(handle);
  return found;
}

td::Status fsync_directory(const std::string& dir) {
  const int fd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0) {
    return td::Status::Error(PSTRING() << "cannot open " << dir << ": " << errno_text());
  }
  const int rc = ::fsync(fd);
  const int error = errno;
  ::close(fd);
  if (rc != 0) {
    return td::Status::Error(PSTRING() << "cannot flush " << dir << ": " << std::strerror(error));
  }
  return td::Status::OK();
}

std::string parent_of(const std::string& path) {
  auto slash = path.find_last_of('/');
  if (slash == std::string::npos) {
    return ".";
  }
  if (slash == 0) {
    return "/";
  }
  return path.substr(0, slash);
}

}  // namespace

std::string to_string(const Decision& decision) {
  switch (decision.kind) {
    case DecisionKind::Notarize:
      return PSTRING() << "notarize(slot=" << decision.slot << ", " << decision.candidate.to_hex() << ")";
    case DecisionKind::Finalize:
      return PSTRING() << "finalize(slot=" << decision.slot << ", " << decision.candidate.to_hex() << ")";
    case DecisionKind::Skip:
      return PSTRING() << "skip(slot=" << decision.slot << ")";
    case DecisionKind::LeaderWindow:
      return PSTRING() << "leader_window(" << decision.slot << ")";
  }
  return "?";
}

// ===== DecisionIndex =====

Check DecisionIndex::check(const Decision& decision) const {
  if (decision.kind == DecisionKind::LeaderWindow) {
    return leader_windows_.contains(decision.slot) ? Check::Same : Check::New;
  }
  auto it = slots_.find(decision.slot);
  if (it == slots_.end()) {
    return Check::New;
  }
  const Slot& slot = it->second;
  switch (decision.kind) {
    case DecisionKind::Notarize:
      if (slot.notarize.has_value()) {
        return *slot.notarize == decision.candidate ? Check::Same : Check::Conflict;
      }
      if (slot.finalize.has_value() && *slot.finalize != decision.candidate) {
        return Check::Conflict;
      }
      return Check::New;
    case DecisionKind::Finalize:
      if (slot.finalize.has_value()) {
        return *slot.finalize == decision.candidate ? Check::Same : Check::Conflict;
      }
      if (slot.skip) {
        return Check::Conflict;
      }
      if (slot.notarize.has_value() && *slot.notarize != decision.candidate) {
        return Check::Conflict;
      }
      return Check::New;
    case DecisionKind::Skip:
      if (slot.skip) {
        return Check::Same;
      }
      if (slot.finalize.has_value()) {
        return Check::Conflict;
      }
      return Check::New;
    case DecisionKind::LeaderWindow:
      break;
  }
  return Check::Conflict;
}

void DecisionIndex::apply(const Decision& decision) {
  ++count_;
  if (decision.kind == DecisionKind::LeaderWindow) {
    leader_windows_.insert(decision.slot);
    return;
  }
  Slot& slot = slots_[decision.slot];
  switch (decision.kind) {
    case DecisionKind::Notarize:
      slot.notarize = decision.candidate;
      break;
    case DecisionKind::Finalize:
      slot.finalize = decision.candidate;
      break;
    case DecisionKind::Skip:
      slot.skip = true;
      break;
    case DecisionKind::LeaderWindow:
      break;
  }
}

std::optional<std::int64_t> DecisionIndex::seq_of(const Decision& decision) const {
  for (const auto& [recorded, seq] : seqs_) {
    if (recorded == decision) {
      return seq;
    }
  }
  return std::nullopt;
}

void DecisionIndex::remember_seq(const Decision& decision, std::int64_t seq) {
  seqs_.emplace_back(decision, seq);
}

// ===== File operations =====

long FileOps::pwrite(int fd, const void* data, std::size_t size, long offset) {
  return static_cast<long>(::pwrite(fd, data, size, static_cast<off_t>(offset)));
}

int FileOps::fdatasync(int fd) {
  return ::fdatasync(fd);
}

int FileOps::fsync(int fd) {
  return ::fsync(fd);
}

int FileOps::ftruncate(int fd, long length) {
  return ::ftruncate(fd, static_cast<off_t>(length));
}

td::Status FileOps::replace_file(const std::string& dir, const std::string& name, const std::string& bytes) {
  const std::string final_path = dir + "/" + name;
  const std::string temp_path = final_path + ".tmp";
  const int fd = ::open(temp_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0) {
    return td::Status::Error(PSTRING() << "cannot create " << temp_path << ": " << errno_text());
  }
  std::size_t written = 0;
  while (written < bytes.size()) {
    const auto n = ::write(fd, bytes.data() + written, bytes.size() - written);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      const int error = errno;
      ::close(fd);
      return td::Status::Error(PSTRING() << "cannot write " << temp_path << ": " << std::strerror(error));
    }
    written += static_cast<std::size_t>(n);
  }
  if (::fsync(fd) != 0) {
    const int error = errno;
    ::close(fd);
    return td::Status::Error(PSTRING() << "cannot flush " << temp_path << ": " << std::strerror(error));
  }
  ::close(fd);
  if (::rename(temp_path.c_str(), final_path.c_str()) != 0) {
    return td::Status::Error(PSTRING() << "cannot rename " << temp_path << ": " << errno_text());
  }
  return fsync_directory(dir);
}

std::shared_ptr<FileOps> default_file_ops() {
  static auto ops = std::make_shared<FileOps>();
  return ops;
}

// ===== Bindings =====

namespace {

td::Result<Binding> binding_from(const struct statx& stx) {
  if ((stx.stx_mask & STATX_BTIME) == 0) {
    return td::Status::Error(
        "the filesystem reports no birth time, so this file cannot be bound to what it was "
        "created as");
  }
  Binding binding;
  binding.ino = stx.stx_ino;
  binding.btime_sec = stx.stx_btime.tv_sec;
  binding.btime_nsec = stx.stx_btime.tv_nsec;
  return binding;
}

}  // namespace

td::Result<Binding> binding_of(const std::string& path) {
  struct statx stx{};
  if (::statx(AT_FDCWD, path.c_str(), AT_SYMLINK_NOFOLLOW, STATX_INO | STATX_BTIME, &stx) != 0) {
    return td::Status::Error(PSTRING() << "cannot inspect " << path << ": " << errno_text());
  }
  return binding_from(stx);
}

td::Result<Binding> binding_of_fd(int fd) {
  struct statx stx{};
  if (::statx(fd, "", AT_EMPTY_PATH, STATX_INO | STATX_BTIME, &stx) != 0) {
    return td::Status::Error(PSTRING() << "cannot inspect an open log: " << errno_text());
  }
  return binding_from(stx);
}

// ===== Records =====

std::array<unsigned char, 16> chain_start(const td::Bits256& session) {
  std::string seed = "tos-signing-decision-log-v1";
  seed.append(reinterpret_cast<const char*>(session.data()), 32);
  std::array<unsigned char, 16> zero{};
  return chain_step(zero, seed);
}

std::string encode_record(const Decision& decision, std::int64_t seq, const std::array<unsigned char, 16>& previous,
                          std::array<unsigned char, 16>& next) {
  std::string out;
  out.reserve(kRecordBytes);
  out.push_back(static_cast<char>(kRecordTag));
  out.push_back(static_cast<char>(decision.kind));
  out.push_back(0);
  out.push_back(0);
  put_u32(out, decision.slot);
  put_u64(out, static_cast<std::uint64_t>(seq));
  put_bits(out, decision.candidate);
  next = chain_step(previous, out);
  out.append(reinterpret_cast<const char*>(next.data()), next.size());
  CHECK(out.size() == kRecordBytes);
  return out;
}

td::Result<LoadedLog> load_log(int fd, const td::Bits256& session) {
  struct stat st{};
  if (::fstat(fd, &st) != 0) {
    return td::Status::Error(PSTRING() << "cannot inspect the log: " << errno_text());
  }
  if (!S_ISREG(st.st_mode)) {
    return td::Status::Error("the log is not a regular file");
  }
  // Checked before anything is read or allocated.
  if (st.st_size < 0 || static_cast<std::uint64_t>(st.st_size) > kMaxLogBytes + kRecordBytes) {
    return td::Status::Error(PSTRING() << "the log is " << st.st_size << " bytes, above the limit of " << kMaxLogBytes);
  }
  const auto size = static_cast<std::size_t>(st.st_size);
  std::string bytes(size, '\0');
  std::size_t read_so_far = 0;
  while (read_so_far < size) {
    const auto n = ::pread(fd, bytes.data() + read_so_far, size - read_so_far, static_cast<off_t>(read_so_far));
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return td::Status::Error(PSTRING() << "cannot read the log: " << errno_text());
    }
    read_so_far += static_cast<std::size_t>(n);
  }
  LoadedLog loaded;
  loaded.chain = chain_start(session);
  const std::size_t records = size / kRecordBytes;
  loaded.torn_tail = size % kRecordBytes != 0;
  if (records > kMaxLogRecords) {
    return td::Status::Error(PSTRING() << "the log holds " << records << " records, above the limit of "
                                       << kMaxLogRecords);
  }
  DecisionIndex index;
  for (std::size_t i = 0; i < records; ++i) {
    td::Slice record(bytes.data() + i * kRecordBytes, kRecordBytes);
    Reader in(record);
    std::uint8_t tag = 0;
    std::uint8_t kind = 0;
    std::uint8_t pad0 = 0;
    std::uint8_t pad1 = 0;
    std::uint32_t slot = 0;
    std::uint64_t seq = 0;
    td::Bits256 candidate;
    if (!in.u8(tag) || !in.u8(kind) || !in.u8(pad0) || !in.u8(pad1) || !in.u32(slot) || !in.u64(seq) ||
        !in.bits(candidate)) {
      return td::Status::Error(PSTRING() << "log record " << i << " is truncated");
    }
    if (tag != kRecordTag || !valid_kind(kind) || pad0 != 0 || pad1 != 0) {
      return td::Status::Error(PSTRING() << "log record " << i << " is malformed");
    }
    const auto expected = chain_step(loaded.chain, record.substr(0, kRecordBytes - 16));
    if (std::memcmp(expected.data(), record.data() + kRecordBytes - 16, 16) != 0) {
      return td::Status::Error(PSTRING() << "log record " << i << " breaks the chain");
    }
    if (seq != i) {
      return td::Status::Error(PSTRING() << "log record " << i << " carries sequence number " << seq);
    }
    Decision decision{static_cast<DecisionKind>(kind), slot, candidate};
    if (!has_candidate(decision.kind) && !decision.candidate.is_zero()) {
      return td::Status::Error(PSTRING() << "log record " << i << " carries a candidate it cannot have");
    }
    if (index.check(decision) != Check::New) {
      return td::Status::Error(PSTRING() << "log record " << i << " (" << to_string(decision)
                                         << ") repeats or conflicts with an earlier decision");
    }
    index.apply(decision);
    loaded.chain = expected;
    loaded.decisions.emplace_back(static_cast<std::int64_t>(seq), decision);
  }
  loaded.verified_bytes = records * kRecordBytes;
  return loaded;
}

// ===== SessionDecisionLog =====

SessionDecisionLog::SessionDecisionLog(td::Bits256 session, int fd, LoadedLog loaded, std::shared_ptr<FileOps> ops,
                                       std::shared_ptr<std::atomic<bool>> stopped, WriteGate gate)
    : session_(session)
    , fd_(fd)
    , verified_bytes_(loaded.verified_bytes)
    , chain_(loaded.chain)
    , ops_(std::move(ops))
    , stopped_(std::move(stopped))
    , gate_(std::move(gate)) {
  for (const auto& [seq, decision] : loaded.decisions) {
    index_.apply(decision);
    index_.remember_seq(decision, seq);
    next_seq_ = seq + 1;
  }
}

SessionDecisionLog::~SessionDecisionLog() {
  for (auto& pending : queue_) {
    pending.promise.set_value(Reservation{ReserveResult::Failed, 0});
  }
  queue_.clear();
  if (fd_ >= 0) {
    ::close(fd_);
  }
}

td::actor::Task<Reservation> SessionDecisionLog::reserve(Decision decision) {
  auto [task, promise] = td::actor::StartedTask<Reservation>::make_bridge();
  queue_.push_back(Pending{decision, std::move(promise)});
  if (!draining_) {
    draining_ = true;
    drain().start().detach();
  }
  co_return co_await std::move(task);
}

td::actor::Task<std::size_t> SessionDecisionLog::durable_records() {
  co_return verified_bytes_ / kRecordBytes;
}

// One request at a time, from its check to its acknowledgement: the next request is not
// looked at until the one before it has been written, flushed and applied to the index, or
// refused. A suspension anywhere in between (the test gate, or any future asynchronous
// write) cannot let a second request pass the check against a stale index.
td::actor::Task<> SessionDecisionLog::drain() {
  while (!queue_.empty()) {
    auto pending = std::move(queue_.front());
    queue_.pop_front();
    auto result = co_await handle(pending.decision);
    pending.promise.set_value(std::move(result));
  }
  draining_ = false;
  co_return td::Unit{};
}

td::actor::Task<Reservation> SessionDecisionLog::handle(const Decision& decision) {
  if (failed_) {
    co_return Reservation{ReserveResult::Failed, 0};
  }
  switch (index_.check(decision)) {
    case Check::Same:
      co_return Reservation{ReserveResult::AlreadyDecided, index_.seq_of(decision).value_or(0)};
    case Check::Conflict:
      LOG(ERROR) << "signing decision log " << session_.to_hex() << ": refusing " << to_string(decision)
                 << ", which conflicts with a decision already recorded";
      co_return Reservation{ReserveResult::Conflict, 0};
    case Check::New:
      break;
  }
  if (index_.size() >= kMaxLogRecords) {
    LOG(ERROR) << "signing decision log " << session_.to_hex() << " is full at " << kMaxLogRecords
               << " records; this session signs nothing more";
    failed_ = true;
    stopped_->store(true, std::memory_order_release);
    co_return Reservation{ReserveResult::Failed, 0};
  }
  if (gate_) {
    co_await gate_(decision);
  }
  std::array<unsigned char, 16> next{};
  const auto record = encode_record(decision, next_seq_, chain_, next);
  const long written = ops_->pwrite(fd_, record.data(), record.size(), static_cast<long>(verified_bytes_));
  const bool durable = written == static_cast<long>(record.size()) && ops_->fdatasync(fd_) == 0;
  if (!durable) {
    LOG(ERROR) << "signing decision log " << session_.to_hex() << ": " << to_string(decision)
               << " was not recorded (wrote " << written << " bytes); not signing it";
    if (!recover()) {
      LOG(ERROR) << "signing decision log " << session_.to_hex()
                 << " could not be restored to its last recorded decision; this session signs nothing more";
      failed_ = true;
      stopped_->store(true, std::memory_order_release);
    }
    co_return Reservation{ReserveResult::Failed, 0};
  }
  index_.apply(decision);
  index_.remember_seq(decision, next_seq_);
  verified_bytes_ += record.size();
  chain_ = next;
  co_return Reservation{ReserveResult::Reserved, next_seq_++};
}

// After a write that was not acknowledged, bytes of it may be in the file. Nothing more is
// appended until the file is cut back to the last acknowledged record, that is durable, and
// a fresh read of the file shows exactly the records and chain this process acknowledged.
bool SessionDecisionLog::recover() {
  if (ops_->ftruncate(fd_, static_cast<long>(verified_bytes_)) != 0 || ops_->fsync(fd_) != 0) {
    return false;
  }
  auto reloaded = load_log(fd_, session_);
  if (reloaded.is_error()) {
    LOG(ERROR) << "signing decision log " << session_.to_hex() << " after recovery: " << reloaded.error();
    return false;
  }
  const auto& loaded = reloaded.ok();
  return !loaded.torn_tail && loaded.verified_bytes == verified_bytes_ && loaded.chain == chain_;
}

// ===== Admission =====

bool Admission::leader_window_recorded(std::uint32_t window) const {
  for (const auto& [seq, decision] : decisions) {
    if (decision.kind == DecisionKind::LeaderWindow && decision.slot == window) {
      return true;
    }
  }
  return false;
}

std::shared_ptr<const Admission> Admission::fence(td::Bits256 session, std::string reason) {
  auto admission = std::make_shared<Admission>();
  admission->fenced = true;
  admission->reason = std::move(reason);
  admission->session = session;
  return admission;
}

std::shared_ptr<const Admission> admission_for_validator_group(std::shared_ptr<const Admission> admission,
                                                               td::Bits256 session) {
  if (admission != nullptr) {
    return admission;
  }
  LOG(ERROR) << "signing ledger: a validator group for session " << session.to_hex()
             << " was built without an admission; it signs nothing";
  return Admission::fence(session, "the validator group was built without an admission from the signing ledger");
}

// ===== Header =====

std::string encode_header(const Header& header) {
  std::string out(kHeaderMagic, sizeof(kHeaderMagic));
  put_bits(out, header.validator);
  put_binding(out, header.dir);
  out.push_back(header.floor.has_value() ? 1 : 0);
  if (header.floor.has_value()) {
    const auto& floor = *header.floor;
    put_u32(out, static_cast<std::uint32_t>(floor.id.workchain));
    put_u64(out, floor.id.shard);
    put_u32(out, floor.id.seqno);
    put_bits(out, floor.root_hash);
    put_bits(out, floor.file_hash);
  }
  out.push_back(static_cast<char>(header.history));
  put_u64(out, header.t0);
  put_u32(out, static_cast<std::uint32_t>(header.fence.size()));
  for (const auto& entry : header.fence) {
    put_u32(out, static_cast<std::uint32_t>(entry.workchain));
    put_u64(out, entry.shard);
    put_u32(out, entry.cc);
  }
  put_u32(out, static_cast<std::uint32_t>(header.entries.size()));
  for (const auto& entry : header.entries) {
    put_bits(out, entry.session);
    put_binding(out, entry.log);
  }
  unsigned char digest[32];
  td::sha256(out, td::MutableSlice(reinterpret_cast<char*>(digest), 32));
  out.append(reinterpret_cast<const char*>(digest), 32);
  return out;
}

td::Result<Header> decode_header(td::Slice bytes) {
  if (bytes.size() > kMaxHeaderBytes) {
    return td::Status::Error(PSTRING() << "the ledger header is " << bytes.size() << " bytes, above the limit");
  }
  if (bytes.size() < sizeof(kHeaderMagic) + 32 || std::memcmp(bytes.data(), kHeaderMagic, sizeof(kHeaderMagic)) != 0) {
    return td::Status::Error("the ledger header is not one");
  }
  const td::Slice body = bytes.substr(0, bytes.size() - 32);
  unsigned char digest[32];
  td::sha256(body, td::MutableSlice(reinterpret_cast<char*>(digest), 32));
  if (std::memcmp(digest, bytes.data() + bytes.size() - 32, 32) != 0) {
    return td::Status::Error("the ledger header fails its checksum");
  }
  Reader in(body.substr(sizeof(kHeaderMagic)));
  Header header;
  std::uint8_t has_floor = 0;
  if (!in.bits(header.validator) || !get_binding(in, header.dir) || !in.u8(has_floor) || has_floor > 1) {
    return td::Status::Error("the ledger header is truncated");
  }
  if (has_floor == 1) {
    std::uint32_t workchain = 0;
    std::uint64_t shard = 0;
    std::uint32_t seqno = 0;
    td::Bits256 root;
    td::Bits256 file;
    if (!in.u32(workchain) || !in.u64(shard) || !in.u32(seqno) || !in.bits(root) || !in.bits(file)) {
      return td::Status::Error("the ledger header's floor is truncated");
    }
    header.floor = BlockIdExt{static_cast<WorkchainId>(workchain), shard, seqno, root, file};
  }
  std::uint8_t history = 0;
  std::uint32_t fence_count = 0;
  if (!in.u8(history) || history > static_cast<std::uint8_t>(History::Established) || !in.u64(header.t0) ||
      !in.u32(fence_count)) {
    return td::Status::Error("the ledger header's history is truncated or unknown");
  }
  header.history = static_cast<History>(history);
  // Checked before anything is allocated for the fence.
  constexpr std::size_t kFenceEntryBytes = 4 + 8 + 4;
  if (fence_count > kMaxFenceEntries || in.remaining() < static_cast<std::size_t>(fence_count) * kFenceEntryBytes) {
    return td::Status::Error(PSTRING() << "the ledger header claims " << fence_count << " fence entries");
  }
  if ((header.history == History::Established) != (fence_count > 0)) {
    return td::Status::Error("the ledger header's fence does not match its history");
  }
  header.fence.reserve(fence_count);
  for (std::uint32_t i = 0; i < fence_count; ++i) {
    std::uint32_t workchain = 0;
    FenceEntry entry;
    if (!in.u32(workchain) || !in.u64(entry.shard) || !in.u32(entry.cc) || entry.cc == kCounterSentinel) {
      return td::Status::Error("the ledger header's fence is truncated or holds no counter");
    }
    entry.workchain = static_cast<std::int32_t>(workchain);
    header.fence.push_back(entry);
  }
  std::uint32_t count = 0;
  if (!in.u32(count)) {
    return td::Status::Error("the ledger header is truncated");
  }
  // Checked before anything is allocated for the entries.
  constexpr std::size_t kEntryBytes = 32 + 20;
  if (count > kMaxEntries || in.remaining() != static_cast<std::size_t>(count) * kEntryBytes) {
    return td::Status::Error(PSTRING() << "the ledger header claims " << count << " entries");
  }
  header.entries.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    HeaderEntry entry;
    if (!in.bits(entry.session) || !get_binding(in, entry.log)) {
      return td::Status::Error("the ledger header's entries are truncated");
    }
    for (const auto& previous : header.entries) {
      if (previous.session == entry.session) {
        return td::Status::Error("the ledger header lists a session twice");
      }
    }
    header.entries.push_back(entry);
  }
  return header;
}

std::string ledger_dir(const std::string& db_root) {
  return db_root + "/consensus/signing-ledger";
}

td::Status create_ledger(const std::string& dir, const td::Bits256& validator, std::shared_ptr<FileOps> ops,
                         std::optional<BlockIdExt> floor) {
  const std::string parent = parent_of(dir);
  if (::mkdir(parent.c_str(), 0700) != 0 && errno != EEXIST) {
    return td::Status::Error(PSTRING() << "cannot create " << parent << ": " << errno_text());
  }
  if (::mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST) {
    return td::Status::Error(PSTRING() << "cannot create " << dir << ": " << errno_text());
  }
  if (file_exists(dir + "/" + kHeaderName) || has_log_files(dir)) {
    return td::Status::Error("a signing ledger, or a log of one, is already there");
  }
  TRY_RESULT(binding, binding_of(dir));
  Header header;
  header.validator = validator;
  header.dir = binding;
  header.floor = floor;
  header.history = History::Complete;
  TRY_STATUS(ops->replace_file(dir, kHeaderName, encode_header(header)));
  return fsync_directory(parent);
}

// ===== The fence =====

std::optional<std::string> fence_block_refusal(const FenceBlock& block, std::uint64_t t0) {
  // In 64 bits, as everything about the margin is.
  if (static_cast<std::uint64_t>(block.gen_utime) < t0 + kHistoryMarginSeconds) {
    return PSTRING() << "generated at " << block.gen_utime << ", before " << t0 + kHistoryMarginSeconds;
  }
  if (block.lineages.empty() || block.lineages.size() > kMaxFenceEntries) {
    return PSTRING() << "a fence of " << block.lineages.size() << " lineages cannot be recorded (between 1 and "
                     << kMaxFenceEntries << ")";
  }
  for (const auto& entry : block.lineages) {
    if (entry.cc == kCounterSentinel) {
      return PSTRING() << "no catchain counter for shard " << ShardIdFull{entry.workchain, entry.shard}.to_str();
    }
  }
  return std::nullopt;
}

std::uint64_t custody_time(double unix_seconds) {
  if (!(unix_seconds > 0)) {
    return 0;
  }
  return static_cast<std::uint64_t>(std::ceil(unix_seconds));
}

bool fenced_by_history(const std::vector<FenceEntry>& fence, ShardIdFull shard, std::uint32_t cc) {
  if (cc == kCounterSentinel) {
    return true;
  }
  bool related = false;
  for (const auto& entry : fence) {
    if (entry.workchain != shard.workchain) {
      continue;
    }
    if (entry.shard != shard.shard && !shard_is_ancestor(entry.shard, shard.shard) &&
        !shard_is_ancestor(shard.shard, entry.shard)) {
      continue;
    }
    related = true;
    // In 64 bits: an entry near the top of the range fences everything above it.
    if (static_cast<std::uint64_t>(cc) <= static_cast<std::uint64_t>(entry.cc) + kFenceCounterMargin) {
      return true;
    }
  }
  // No entry relates to this lineage: what was signed in it before the fence is unknown.
  return !related;
}

// ===== SigningLedger =====

SigningLedger::SigningLedger(std::string dir, std::shared_ptr<FileOps> ops, SessionDecisionLog::WriteGate gate,
                             std::function<double()> clock)
    : dir_(std::move(dir)), ops_(std::move(ops)), gate_(std::move(gate)), clock_(std::move(clock)) {
}

void SigningLedger::start_up() {
  started_at_ = custody_time(clock_ ? clock_() : td::Clocks::system());
  const std::string path = dir_ + "/" + kHeaderName;
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0) {
    if (errno == ENOENT) {
      if (has_log_files(dir_)) {
        status_ = LedgerStatus::Untrusted;
        untrusted_reason_ = "decision logs are present without the ledger header that lists them";
      } else {
        status_ = LedgerStatus::Absent;
        untrusted_reason_ = "this node has no signing ledger";
      }
    } else {
      status_ = LedgerStatus::Untrusted;
      untrusted_reason_ = "the signing ledger cannot be opened: " + errno_text();
    }
    LOG(WARNING) << "signing ledger " << dir_ << ": " << untrusted_reason_
                 << "; a pending ledger for unknown history replaces it at the first admission";
    return;
  }
  struct stat st{};
  std::string bytes;
  bool readable = ::fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size >= 0 &&
                  static_cast<std::uint64_t>(st.st_size) <= kMaxHeaderBytes;
  if (readable) {
    bytes.resize(static_cast<std::size_t>(st.st_size));
    std::size_t got = 0;
    while (readable && got < bytes.size()) {
      const auto n = ::pread(fd, bytes.data() + got, bytes.size() - got, static_cast<off_t>(got));
      if (n < 0 && errno == EINTR) {
        continue;
      }
      readable = n > 0;
      got += readable ? static_cast<std::size_t>(n) : 0;
    }
  }
  ::close(fd);
  if (!readable) {
    status_ = LedgerStatus::Untrusted;
    untrusted_reason_ = "the signing ledger header cannot be read or is above its size limit";
    LOG(ERROR) << "signing ledger " << dir_ << ": " << untrusted_reason_
               << "; a pending ledger for unknown history replaces it at the first admission";
    return;
  }
  auto decoded = decode_header(bytes);
  if (decoded.is_error()) {
    status_ = LedgerStatus::Untrusted;
    untrusted_reason_ = decoded.error().message().str();
    LOG(ERROR) << "signing ledger " << dir_ << ": " << untrusted_reason_
               << "; a pending ledger for unknown history replaces it at the first admission";
    return;
  }
  auto binding = binding_of(dir_);
  if (binding.is_error() || !(binding.ok() == decoded.ok().dir)) {
    status_ = LedgerStatus::Untrusted;
    untrusted_reason_ = binding.is_error() ? binding.error().message().str()
                                           : std::string(
                                                 "the signing ledger directory is not the one it was "
                                                 "created as: it was copied, restored or recreated");
    LOG(ERROR) << "signing ledger " << dir_ << ": " << untrusted_reason_
               << "; a pending ledger for unknown history replaces it at the first admission";
    return;
  }
  header_ = decoded.move_as_ok();
  status_ = LedgerStatus::Trusted;
  LOG(INFO) << "signing ledger " << dir_ << ": trusted, " << header_.entries.size() << " sessions";
}

std::string SigningLedger::log_path(const td::Bits256& session) const {
  return dir_ + "/" + kLogPrefix + session.to_hex();
}

td::Status SigningLedger::write_header() {
  auto bytes = encode_header(header_);
  if (bytes.size() > kMaxHeaderBytes) {
    return td::Status::Error("the signing ledger header would exceed its size limit");
  }
  return ops_->replace_file(dir_, kHeaderName, bytes);
}

td::actor::Task<std::shared_ptr<const Admission>> SigningLedger::admit(td::Bits256 validator, td::Bits256 session,
                                                                       ShardIdFull shard, std::uint32_t cc,
                                                                       IdentityHistory history) {
  co_return admit_now(validator, session, shard, cc, history);
}

td::Status SigningLedger::establish(const FenceBlock& block) {
  auto previous = header_;
  header_.history = History::Established;
  header_.fence = block.lineages;
  if (!header_.floor.has_value() || header_.floor->seqno() < block.block.seqno()) {
    header_.floor = block.block;
  }
  if (auto written = write_header(); written.is_error()) {
    header_ = std::move(previous);
    return written;
  }
  std::string lineages_text;
  for (const auto& entry : header_.fence) {
    lineages_text += PSTRING() << " " << ShardIdFull{entry.workchain, entry.shard}.to_str() << "=" << entry.cc;
  }
  LOG(WARNING) << "signing ledger: unknown history fenced at " << block.block.to_str() << " (generated "
               << block.gen_utime << ", waiting from " << header_.t0 << ") over " << header_.fence.size()
               << " lineages; sessions more than " << kFenceCounterMargin
               << " catchain counters above them sign again; counters:" << lineages_text;
  return td::Status::OK();
}

td::Status SigningLedger::start_unknown_history(const td::Bits256& validator, const IdentityHistory& history) {
  const std::string path = dir_ + "/" + kHeaderName;
  if (file_exists(path)) {
    // The untrusted header is kept beside the new one, never deleted; at most kMaxSetAside.
    std::string aside;
    for (std::size_t n = 0; n < kMaxSetAside && aside.empty(); ++n) {
      auto candidate = PSTRING() << path << ".untrusted." << n;
      if (!file_exists(candidate)) {
        aside = candidate;
      }
    }
    if (aside.empty()) {
      return td::Status::Error(PSTRING() << kMaxSetAside << " untrusted ledger headers are already set aside");
    }
    if (::rename(path.c_str(), aside.c_str()) != 0) {
      return td::Status::Error(PSTRING() << "cannot set the untrusted ledger header aside: " << errno_text());
    }
    LOG(WARNING) << "signing ledger: the untrusted header was set aside as " << aside;
  }
  const std::string parent = parent_of(dir_);
  if (::mkdir(parent.c_str(), 0700) != 0 && errno != EEXIST) {
    return td::Status::Error(PSTRING() << "cannot create " << parent << ": " << errno_text());
  }
  if (::mkdir(dir_.c_str(), 0700) != 0 && errno != EEXIST) {
    return td::Status::Error(PSTRING() << "cannot create " << dir_ << ": " << errno_text());
  }
  TRY_RESULT(binding, binding_of(dir_));
  Header header;
  header.validator = validator;
  header.dir = binding;
  header.history = History::Pending;
  // Never earlier than this actor's start: a later t0 only ever fences more.
  header.t0 = std::max(started_at_, history.t0);
  const bool settled = history.fence_block.has_value() && !fence_block_refusal(*history.fence_block, header.t0);
  if (settled) {
    // The fence block this process applied after taking custody of the identity, before
    // its first admission: the history is established in the same write.
    header.history = History::Established;
    header.fence = history.fence_block->lineages;
    header.floor = history.fence_block->block;
  }
  TRY_STATUS(ops_->replace_file(dir_, kHeaderName, encode_header(header)));
  TRY_STATUS(fsync_directory(parent));
  header_ = std::move(header);
  status_ = LedgerStatus::Trusted;
  if (settled) {
    LOG(WARNING) << "signing ledger: this node's earlier signing is unknown; fenced at the block "
                 << history.fence_block->block.to_str() << " this process applied at or after "
                 << header_.t0 + kHistoryMarginSeconds << ", before its first admission";
  } else {
    LOG(WARNING) << "signing ledger: this node's earlier signing is unknown; every session is fenced until a "
                    "masterchain block generated at or after "
                 << header_.t0 + kHistoryMarginSeconds;
  }
  return td::Status::OK();
}

std::shared_ptr<const Admission> SigningLedger::admit_now(const td::Bits256& validator, const td::Bits256& session,
                                                          ShardIdFull shard, std::uint32_t cc,
                                                          const IdentityHistory& history) {
  if (auto it = admitted_.find(session); it != admitted_.end()) {
    return it->second;
  }
  if (status_ != LedgerStatus::Trusted) {
    if (auto started = start_unknown_history(validator, history); started.is_error()) {
      LOG(ERROR) << "signing ledger: no pending ledger could be created: " << started << "; no session will sign";
      // The original trust failure is kept as it is; each reply carries it with only this
      // attempt's error, so nothing retained grows with the number of admissions.
      return Admission::fence(
          session, PSTRING() << untrusted_reason_ << "; no pending ledger could be created: " << started.message());
    }
  }
  if (header_.validator != validator) {
    return Admission::fence(session, "the signing ledger belongs to another validator");
  }
  if (header_.history == History::Pending && history.fence_block.has_value()) {
    // A pending ledger of an earlier process: this process's own fence block settles it,
    // measured from the later of the two waits.
    const auto t0 = std::max(header_.t0, history.t0);
    if (!fence_block_refusal(*history.fence_block, t0)) {
      if (auto established = establish(*history.fence_block); established.is_error()) {
        LOG(ERROR) << "signing ledger: the fence block was not recorded: " << established;
      }
    }
  }
  if (header_.history == History::Pending) {
    auto fenced = std::make_shared<Admission>();
    fenced->fenced = true;
    fenced->history_unknown = true;
    fenced->session = session;
    fenced->reason = PSTRING() << "this node's earlier signing is unknown; waiting for a masterchain block generated "
                                  "at or after "
                               << std::max(header_.t0, history.t0) + kHistoryMarginSeconds;
    return fenced;
  }
  if (header_.history == History::Established && fenced_by_history(header_.fence, shard, cc)) {
    return Admission::fence(session, PSTRING() << "the session of " << shard.to_str() << " with catchain counter " << cc
                                               << " is at or below the unknown-history fence");
  }
  const std::string path = log_path(session);
  auto entry = std::find_if(header_.entries.begin(), header_.entries.end(),
                            [&](const HeaderEntry& e) { return e.session == session; });
  int fd = -1;
  LoadedLog loaded;
  loaded.chain = chain_start(session);
  auto create_and_bind = [&](std::vector<HeaderEntry>::iterator at) -> std::optional<std::string> {
    fd = ::open(path.c_str(), O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
      return "cannot create the decision log: " + errno_text();
    }
    if (ops_->fsync(fd) != 0) {
      return "cannot flush the new decision log: " + errno_text();
    }
    if (auto flushed = fsync_directory(dir_); flushed.is_error()) {
      return flushed.message().str();
    }
    auto bound = binding_of_fd(fd);
    if (bound.is_error()) {
      return bound.error().message().str();
    }
    at->log = bound.move_as_ok();
    if (auto written = write_header(); written.is_error()) {
      return written.message().str();
    }
    return std::nullopt;
  };
  auto fail = [&](std::string reason) {
    if (fd >= 0) {
      ::close(fd);
    }
    LOG(ERROR) << "signing ledger: session " << session.to_hex() << " fenced: " << reason;
    return Admission::fence(session, std::move(reason));
  };

  if (entry == header_.entries.end()) {
    if (header_.entries.size() >= kMaxEntries) {
      return fail(PSTRING() << "the signing ledger already lists " << kMaxEntries << " sessions");
    }
    if (file_exists(path)) {
      return fail("a decision log exists for this session but the ledger does not list it");
    }
    // The entry is durable before its log exists, so a log is never one the ledger does not
    // know about; its binding follows once the file exists.
    header_.entries.push_back(HeaderEntry{session, Binding{}});
    if (auto written = write_header(); written.is_error()) {
      header_.entries.pop_back();
      return fail(written.message().str());
    }
    entry = header_.entries.end() - 1;
    if (auto refused = create_and_bind(entry)) {
      return fail(*refused);
    }
  } else if (entry->log.empty()) {
    // A crash between creating the entry and binding its log. Nothing was recorded under an
    // unbound log, because nothing is acknowledged before the binding is durable.
    if (!file_exists(path)) {
      if (auto refused = create_and_bind(entry)) {
        return fail(*refused);
      }
    } else {
      fd = ::open(path.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
      struct stat st{};
      if (fd < 0 || ::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        return fail("the unbound decision log cannot be opened");
      }
      if (st.st_size != 0) {
        return fail("an unbound decision log holds records");
      }
      auto bound = binding_of_fd(fd);
      if (bound.is_error()) {
        return fail(bound.error().message().str());
      }
      entry->log = bound.move_as_ok();
      if (auto written = write_header(); written.is_error()) {
        return fail(written.message().str());
      }
    }
  } else {
    fd = ::open(path.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
      return fail("the decision log this session recorded into is gone: " + errno_text());
    }
    auto bound = binding_of_fd(fd);
    if (bound.is_error()) {
      return fail(bound.error().message().str());
    }
    if (!(bound.ok() == entry->log)) {
      return fail("the decision log is not the one this session recorded into: it was copied, restored or recreated");
    }
    auto read = load_log(fd, session);
    if (read.is_error()) {
      return fail("the decision log is damaged: " + read.error().message().str());
    }
    loaded = read.move_as_ok();
    if (loaded.torn_tail) {
      // A record that was being written when the process stopped. It was never acknowledged,
      // so nothing was signed for it.
      if (ops_->ftruncate(fd, static_cast<long>(loaded.verified_bytes)) != 0 || ops_->fsync(fd) != 0) {
        return fail("the decision log's unfinished last record cannot be removed: " + errno_text());
      }
      loaded.torn_tail = false;
    }
  }

  auto stopped = std::make_shared<std::atomic<bool>>(false);
  auto admission = std::make_shared<Admission>();
  admission->fenced = false;
  admission->session = session;
  admission->decisions = loaded.decisions;
  admission->stopped = stopped;
  auto actor = td::actor::create_actor<SessionDecisionLog>(PSTRING() << "DecisionLog." << session.to_hex().substr(0, 8),
                                                           session, fd, std::move(loaded), ops_, stopped, gate_);
  admission->log = actor.get();
  logs_[session] = std::move(actor);
  admitted_[session] = admission;
  return admission;
}

td::actor::Task<> SigningLedger::prune(std::vector<td::Bits256> sessions, BlockIdExt floor) {
  if (status_ != LedgerStatus::Trusted) {
    co_return td::Unit{};
  }
  const bool raise = !header_.floor.has_value() || header_.floor->seqno() < floor.seqno();
  std::set<td::Bits256> drop(sessions.begin(), sessions.end());
  auto previous = header_;
  std::erase_if(header_.entries, [&](const HeaderEntry& entry) { return drop.contains(entry.session); });
  if (raise) {
    header_.floor = floor;
  }
  if (header_.entries.size() == previous.entries.size() && !raise) {
    co_return td::Unit{};
  }
  if (auto written = write_header(); written.is_error()) {
    header_ = std::move(previous);
    LOG(ERROR) << "signing ledger: pruning was not recorded: " << written;
    co_return written.move_as_error();
  }
  // The header no longer lists them; only now may their logs go.
  for (const auto& session : drop) {
    admitted_.erase(session);
    logs_.erase(session);
    ::unlink(log_path(session).c_str());
  }
  co_return td::Unit{};
}

td::actor::Task<std::optional<BlockIdExt>> SigningLedger::floor() {
  co_return header_.floor;
}

td::actor::Task<LedgerStatus> SigningLedger::status() {
  co_return status_;
}

td::actor::Task<std::string> SigningLedger::untrusted_reason() {
  co_return status_ == LedgerStatus::Trusted ? std::string() : untrusted_reason_;
}

td::actor::Task<History> SigningLedger::history() {
  co_return header_.history;
}

td::actor::Task<bool> SigningLedger::offer_fence_block(td::Bits256 validator, std::uint64_t t0, FenceBlock block) {
  if (status_ != LedgerStatus::Trusted) {
    // No ledger yet: the first admission creates one, from the same fence block.
    co_return false;
  }
  if (header_.validator != validator) {
    // Another identity's ledger; its admissions are fenced whatever this block is.
    co_return false;
  }
  if (header_.history != History::Pending) {
    co_return true;
  }
  if (auto refused = fence_block_refusal(block, std::max(header_.t0, t0))) {
    LOG(WARNING) << "signing ledger: block " << block.block.to_str() << " cannot be the fence block: " << *refused
                 << "; the history stays pending";
    co_return false;
  }
  if (auto established = establish(block); established.is_error()) {
    LOG(ERROR) << "signing ledger: the fence block was not recorded: " << established;
    co_return false;
  }
  co_return true;
}

}  // namespace tos::validator::consensus::signing
