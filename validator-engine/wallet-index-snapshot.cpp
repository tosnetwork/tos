/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#include <algorithm>
#include <array>
#include <cerrno>
#include <filesystem>
#include <functional>
#include <limits>

#include "wallet-index-snapshot.h"

#if defined(__linux__) || defined(__APPLE__)
#include <fcntl.h>
#include <unistd.h>
#endif
#if defined(__linux__)
#include <sys/syscall.h>
#elif defined(__APPLE__)
#include <stdio.h>
#endif

#include "td/db/RocksDb.h"
#include "td/utils/ScopeGuard.h"
#include "td/utils/crypto.h"
#include "td/utils/logging.h"
#include "td/utils/port/FileFd.h"
#include "td/utils/port/path.h"

namespace tos_wallet_index {
namespace {
namespace fs = std::filesystem;
constexpr char kMagic[] = "TOSIDX01";
constexpr size_t kChunk = 64u << 10;
constexpr size_t kBatchBytes = 1u << 20;

td::Status check_cancelled(const WalletSnapshotCancel& cancelled) {
  return cancelled && cancelled() ? td::Status::Error("index snapshot interrupted") : td::Status::OK();
}

void put_u32(char* out, uint32_t value) {
  for (int i = 3; i >= 0; --i) {
    out[i] = static_cast<char>(value & 255);
    value >>= 8;
  }
}

uint32_t get_u32(const char* in) {
  uint32_t value = 0;
  for (int i = 0; i < 4; ++i)
    value = (value << 8) | static_cast<unsigned char>(in[i]);
  return value;
}

td::Status read_exact(td::FileFd& file, td::MutableSlice bytes, td::Sha256State& hash,
                      const WalletSnapshotCancel& cancelled, uint64_t& remaining) {
  if (bytes.size() > remaining)
    return td::Status::Error("truncated index snapshot");
  while (!bytes.empty()) {
    TRY_STATUS(check_cancelled(cancelled));
    auto part = bytes.substr(0, std::min(bytes.size(), kChunk));
    TRY_RESULT(count, file.read(part));
    if (count == 0)
      return td::Status::Error("truncated index snapshot");
    hash.feed(part.substr(0, count));
    bytes.remove_prefix(count);
    remaining -= count;
  }
  return td::Status::OK();
}

td::Status write_hashed(td::FileFd& file, td::Slice bytes, td::Sha256State& hash,
                        const WalletSnapshotCancel& cancelled) {
  while (!bytes.empty()) {
    TRY_STATUS(check_cancelled(cancelled));
    auto part = bytes.substr(0, std::min(bytes.size(), kChunk));
    TRY_STATUS(file.write_all(part));
    hash.feed(part);
    bytes.remove_prefix(part.size());
  }
  return td::Status::OK();
}

td::Status check_lengths(size_t key, size_t value) {
  if (key == 0 || key > kWalletSnapshotMaxKeyBytes || value > kWalletSnapshotMaxValueBytes)
    return td::Status::Error("index snapshot record exceeds transfer limits");
  return td::Status::OK();
}

td::Status validate_checkpoint(const WalletIndexDb::ReplayCheckpoint& checkpoint) {
  if (checkpoint.anchor.seqno() != 1 || checkpoint.committed.seqno() == 0 || checkpoint.anchor.root_hash.is_zero() ||
      checkpoint.anchor.file_hash.is_zero() || checkpoint.committed.root_hash.is_zero() ||
      checkpoint.committed.file_hash.is_zero())
    return td::Status::Error("index snapshot needs a committed replay checkpoint");
  return td::Status::OK();
}

using AcceptRecord = std::function<td::Status(td::Slice, td::Slice)>;

// The records an untrusted import keeps: the schema, the replay checkpoint
// and account history rows (0x12 + account(32) + ~lt(8)). Everything else is
// derived again by the importing node, never taken from the publisher.
bool untrusted_record(td::Slice key) {
  return key == td::Slice("\0\1", 2) || key == td::Slice("\0\x20", 2) || (key.size() == 41 && key[0] == '\x12');
}

// `expected` is the trusted digest the file must have, or null for an
// untrusted import, whose content is checked against the chain instead.
td::Result<WalletIndexSnapshotInfo> scan(td::FileFd& file, const td::Bits256* expected,
                                         const WalletSnapshotCancel& cancelled, const AcceptRecord& accept = {},
                                         uint64_t expected_size = 0) {
  TRY_RESULT(size, file.get_size());
  if (size < 0 || (expected_size != 0 && static_cast<uint64_t>(size) != expected_size))
    return td::Status::Error("index snapshot size changed after verification");
  uint64_t remaining = static_cast<uint64_t>(size);
  TRY_STATUS(file.seek(0));
  td::Sha256State hash;
  hash.init();
  char header[12];
  TRY_STATUS(read_exact(file, td::MutableSlice(header, sizeof(header)), hash, cancelled, remaining));
  if (td::Slice(header, 8) != td::Slice(kMagic, 8) || get_u32(header + 8) != kWalletIndexSchemaVersion)
    return td::Status::Error("unsupported index snapshot format or schema");
  WalletIndexSnapshotInfo info;
  bool schema_seen = false, checkpoint_seen = false;
  td::optional<std::string> state_record, verification_record;
  std::string previous;
  std::array<char, kChunk> scratch{};
  for (;;) {
    char lengths[8];
    TRY_STATUS(read_exact(file, td::MutableSlice(lengths, sizeof(lengths)), hash, cancelled, remaining));
    auto key_size = get_u32(lengths), value_size = get_u32(lengths + 4);
    if (key_size == 0 && value_size == 0)
      break;
    TRY_STATUS(check_lengths(key_size, value_size));
    std::string key(key_size, '\0');
    TRY_STATUS(read_exact(file, td::MutableSlice(key), hash, cancelled, remaining));
    if (!previous.empty() && key <= previous)
      return td::Status::Error("index snapshot keys are not strictly ordered");
    bool schema = key == std::string("\0\1", 2), checkpoint = key == std::string("\0\x20", 2);
    // The verification state and record decide whether the anchor is
    // authenticated; both are small, bounded by the transfer limit.
    bool provenance = key == std::string("\0\x30", 2) || key == std::string("\0\x31", 2);
    if (schema && value_size != 4)
      return td::Status::Error("invalid index snapshot schema record");
    if (checkpoint && value_size != 162)
      return td::Status::Error("invalid index snapshot checkpoint record");
    if (value_size > remaining)
      return td::Status::Error("truncated index snapshot");
    std::string value;
    if (accept || schema || checkpoint || provenance) {
      value.resize(value_size);
      TRY_STATUS(read_exact(file, td::MutableSlice(value), hash, cancelled, remaining));
    } else {
      size_t value_remaining = value_size;
      while (value_remaining) {
        auto part = std::min(value_remaining, scratch.size());
        TRY_STATUS(read_exact(file, td::MutableSlice(scratch.data(), part), hash, cancelled, remaining));
        value_remaining -= part;
      }
    }
    if (schema) {
      if (get_u32(value.data()) != kWalletIndexSchemaVersion)
        return td::Status::Error("unsupported index snapshot schema record");
      schema_seen = true;
    }
    if (checkpoint) {
      TRY_RESULT(parsed, WalletIndexDb::parse_replay_checkpoint(value));
      TRY_STATUS(validate_checkpoint(parsed));
      info.checkpoint = parsed;
      checkpoint_seen = true;
    }
    if (provenance) {
      (key[1] == '\x30' ? state_record : verification_record) = value;
    }
    if (accept)
      TRY_STATUS(accept(key, value));
    previous = std::move(key);
    ++info.records;
  }
  char extra;
  TRY_RESULT(extra_size, file.read(td::MutableSlice(&extra, 1)));
  if (extra_size != 0 || remaining != 0)
    return td::Status::Error("trailing data in index snapshot");
  if (!schema_seen || !checkpoint_seen)
    return td::Status::Error("index snapshot has no schema or replay checkpoint");
  info.anchor_verified = WalletIndexDb::anchor_verified(state_record ? &state_record.value() : nullptr,
                                                       verification_record ? &verification_record.value() : nullptr);
  hash.extract(info.sha256.as_slice());
  if (expected != nullptr && info.sha256 != *expected)
    return td::Status::Error("index snapshot SHA-256 differs from the trusted digest");
  TRY_RESULT(final_size, file.get_size());
  if (final_size != size)
    return td::Status::Error("index snapshot size changed during verification");
  info.bytes = static_cast<uint64_t>(size);
  return info;
}

td::Result<td::FileFd> open_input(const std::string& path) {
#if defined(__linux__) || defined(__APPLE__)
  // A path type check before open races replacement; a blocking open of a
  // FIFO cannot observe cancellation. Open nonblocking, then check the fd.
  int fd = ::open(path.c_str(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    return td::Status::PosixError(errno, "cannot open index snapshot");
  auto file = td::FileFd::from_native_fd(td::NativeFd(fd));
#else
  TRY_RESULT(file, td::FileFd::open(path, td::FileFd::Read));
#endif
  TRY_RESULT(stat, file.stat());
  if (!stat.is_reg_)
    return td::Status::Error("index snapshot must be a regular file");
  return file;
}

td::Result<fs::path> destination(const std::string& path) {
  fs::path requested(path);
  if (requested.filename().empty() || requested.filename() == "." || requested.filename() == "..")
    return td::Status::Error("index snapshot destination needs a new name");
  std::error_code error;
  auto parent = fs::canonical(requested.has_parent_path() ? requested.parent_path() : fs::path("."), error);
  if (error)
    return td::Status::Error("index snapshot destination parent must exist");
  auto result = parent / requested.filename();
  auto status = fs::symlink_status(result, error);
  if (fs::exists(status) || (error && error != std::errc::no_such_file_or_directory))
    return td::Status::Error("index snapshot destination already exists or cannot be inspected");
  return result;
}

td::Status sync_dir(const fs::path& path) {
  TRY_RESULT(dir, td::FileFd::open(path.string(), td::FileFd::Read));
  return dir.sync();
}

td::Status publish(const std::string& from, const std::string& to) {
#if defined(__linux__)
  if (syscall(SYS_renameat2, AT_FDCWD, from.c_str(), AT_FDCWD, to.c_str(), 1) != 0)
    return td::Status::PosixError(errno, "cannot publish index snapshot without replacing destination");
#elif defined(__APPLE__)
  if (renamex_np(from.c_str(), to.c_str(), RENAME_EXCL) != 0)
    return td::Status::PosixError(errno, "cannot publish index snapshot without replacing destination");
#else
  return td::Status::Error("atomic no-replace snapshot publication is unsupported on this platform");
#endif
  return td::Status::OK();
}

void cleanup(const std::string& path) {
  auto status = td::rmrf(path);
  if (status.is_error())
    LOG(ERROR) << "cannot clean snapshot staging directory " << path << ": " << status;
}
}  // namespace

td::Result<WalletIndexSnapshotInfo> WalletIndexSnapshotFile::create(const std::string& index,
                                                                    const std::string& snapshot,
                                                                    const WalletSnapshotCancel& cancelled) {
  TRY_STATUS(check_cancelled(cancelled));
  TRY_RESULT(target, destination(snapshot));
  std::error_code error;
  if (!fs::is_regular_file(fs::path(index) / "CURRENT", error) || error)
    return td::Status::Error("snapshot source must be an existing wallet index");
  td::RocksDbOptions options;
  options.no_transactions = true;
  options.no_block_cache = true;
  options.write_buffer_size = size_t{16} << 20;
  // Raw open acquires the owner's lock, but never calls migrate_schema.
  // A running service therefore refuses export instead of racing a writer.
  TRY_RESULT(raw, td::RocksDb::open_with_file_limit(index, std::move(options), 128));
  WalletIndexDb db(std::make_unique<td::RocksDb>(std::move(raw)));
  std::string schema;
  TRY_RESULT(found, db.db_->get(td::Slice("\0\1", 2), schema));
  if (found != td::KeyValue::GetStatus::Ok || schema.size() != 4 || get_u32(schema.data()) != kWalletIndexSchemaVersion)
    return td::Status::Error("snapshot source schema differs from this binary");
  TRY_RESULT(checkpoint, db.replay_checkpoint());
  if (!checkpoint)
    return td::Status::Error("snapshot source has no replay checkpoint");
  TRY_STATUS(validate_checkpoint(checkpoint.value()));
  TRY_RESULT(temp, td::mkstemp(target.parent_path().string()));
  auto& file = temp.first;
  bool published = false;
  SCOPE_EXIT {
    file.close();
    if (!published)
      cleanup(temp.second);
  };
  td::Sha256State hash;
  hash.init();
  char header[12];
  td::MutableSlice(header, 8).copy_from(td::Slice(kMagic, 8));
  put_u32(header + 8, kWalletIndexSchemaVersion);
  TRY_STATUS(write_hashed(file, td::Slice(header, sizeof(header)), hash, cancelled));
  WalletIndexSnapshotInfo info;
  info.checkpoint = checkpoint.value();
  {
    std::string state, record;
    TRY_RESULT(has_state, db.db_->get(td::Slice("\0\x30", 2), state));
    TRY_RESULT(has_record, db.db_->get(td::Slice("\0\x31", 2), record));
    info.anchor_verified =
        WalletIndexDb::anchor_verified(has_state == td::KeyValue::GetStatus::Ok ? &state : nullptr,
                                       has_record == td::KeyValue::GetStatus::Ok ? &record : nullptr);
  }
  TRY_STATUS(db.db_->for_each([&](td::Slice key, td::Slice value) {
    TRY_STATUS(check_lengths(key.size(), value.size()));
    char lengths[8];
    put_u32(lengths, static_cast<uint32_t>(key.size()));
    put_u32(lengths + 4, static_cast<uint32_t>(value.size()));
    TRY_STATUS(write_hashed(file, td::Slice(lengths, sizeof(lengths)), hash, cancelled));
    TRY_STATUS(write_hashed(file, key, hash, cancelled));
    TRY_STATUS(write_hashed(file, value, hash, cancelled));
    ++info.records;
    return td::Status::OK();
  }));
  char end[8]{};
  TRY_STATUS(write_hashed(file, td::Slice(end, sizeof(end)), hash, cancelled));
  hash.extract(info.sha256.as_slice());
  TRY_RESULT(size, file.get_size());
  info.bytes = static_cast<uint64_t>(size);
  TRY_STATUS(file.sync());
  TRY_STATUS(check_cancelled(cancelled));
  TRY_STATUS(publish(temp.second, target.string()));
  published = true;
  auto synced = sync_dir(target.parent_path());
  if (synced.is_error())
    return td::Status::Error("snapshot was published, but parent directory sync failed; durability is unconfirmed: " +
                             synced.message().str());
  return info;
}

td::Result<WalletIndexSnapshotInfo> WalletIndexSnapshotFile::verify(const std::string& snapshot,
                                                                    const td::Bits256& expected,
                                                                    const WalletSnapshotCancel& cancelled) {
  TRY_RESULT(file, open_input(snapshot));
  return scan(file, &expected, cancelled);
}

td::Result<WalletIndexSnapshotInfo> WalletIndexSnapshotFile::restore(const std::string& snapshot,
                                                                     const std::string& index,
                                                                     const td::Bits256& expected,
                                                                     const WalletSnapshotCancel& cancelled) {
  return import_staged(snapshot, index, &expected, cancelled);
}

td::Result<WalletIndexSnapshotInfo> WalletIndexSnapshotFile::import_untrusted(const std::string& snapshot,
                                                                              const std::string& index,
                                                                              const WalletSnapshotCancel& cancelled) {
  return import_staged(snapshot, index, nullptr, cancelled);
}

td::Result<WalletIndexSnapshotInfo> WalletIndexSnapshotFile::import_staged(const std::string& snapshot,
                                                                           const std::string& index,
                                                                           const td::Bits256* expected,
                                                                           const WalletSnapshotCancel& cancelled) {
  bool untrusted = expected == nullptr;
  TRY_RESULT(target, destination(index));
  TRY_RESULT(file, open_input(snapshot));
  // Verify before creating any DB, then hash the same descriptor's bytes
  // again as they enter staging. A replaced path or changed file cannot
  // install content different from the operator's trusted digest.
  TRY_RESULT(verified, scan(file, expected, cancelled));
  std::error_code error;
  auto space = fs::space(target.parent_path(), error);
  constexpr uint64_t reserve = uint64_t{128} << 20;
  if (error || verified.bytes > (std::numeric_limits<uint64_t>::max() - reserve) / 3 ||
      space.available < verified.bytes * 3 + reserve)
    return td::Status::Error("insufficient space for staged index restore (3 x snapshot bytes + 128 MiB required)");
  TRY_RESULT(temp, td::mkdtemp(target.parent_path().string(), ".wallet-index-import-"));
  bool published = false;
  SCOPE_EXIT {
    if (!published)
      cleanup(temp);
  };
  td::RocksDbOptions options;
  options.no_transactions = true;
  options.no_block_cache = true;
  options.write_buffer_size = size_t{16} << 20;
  TRY_RESULT(raw, td::RocksDb::open_with_file_limit(temp, std::move(options), 128));
  {
    WalletIndexDb db(std::make_unique<td::RocksDb>(std::move(raw)));
    size_t batch_bytes = 0;
    bool batch_open = false;
    auto begin = [&]() {
      auto status = db.db_->begin_write_batch();
      batch_open = status.is_ok();
      return status;
    };
    auto commit = [&]() {
      // RocksDb consumes the batch before issuing the write, including on
      // I/O failure. There is then no batch left to abort.
      batch_open = false;
      return db.db_->commit_write_batch();
    };
    TRY_STATUS(begin());
    uint64_t kept = 0, dropped = 0;
    auto restored = scan(
        file, expected, cancelled,
        [&](td::Slice key, td::Slice value) {
          if (untrusted && !untrusted_record(key)) {
            ++dropped;
            return td::Status::OK();
          }
          ++kept;
          // Commit before a large record: a batch contains at most 1 MiB of
          // ordinary records or one record at the transfer ceiling.
          if (batch_bytes != 0 && key.size() + value.size() > kBatchBytes - batch_bytes) {
            TRY_STATUS(commit());
            TRY_STATUS(begin());
            batch_bytes = 0;
          }
          TRY_STATUS(db.db_->set(key, value));
          batch_bytes += key.size() + value.size();
          if (batch_bytes >= kBatchBytes) {
            TRY_STATUS(commit());
            TRY_STATUS(begin());
            batch_bytes = 0;
          }
          return td::Status::OK();
        },
        verified.bytes);
    if (restored.is_error()) {
      if (batch_open) {
        auto aborted = db.db_->abort_write_batch();
        if (aborted.is_error())
          LOG(ERROR) << "cannot abort snapshot staging batch: " << aborted;
      }
      return restored.move_as_error();
    }
    TRY_STATUS(commit());
    // The bytes imported must be the bytes first scanned. A trusted restore
    // already checked both scans against the digest; an untrusted import has
    // no digest, so a same-length change between the scans is caught here.
    if (restored.ok().sha256 != verified.sha256)
      return td::Status::Error("index snapshot changed between verification and import");
    if (untrusted) {
      TRY_STATUS(begin());
      TRY_STATUS(db.put_verification_state(VerificationState::Quarantined));
      TRY_STATUS(commit());
      verified.kept = kept;
      verified.dropped = dropped;
      // Whatever the publisher's records claimed, only this node's own
      // check of its block 1 can authenticate the anchor.
      verified.anchor_verified = false;
    }
    TRY_RESULT(checkpoint, db.replay_checkpoint());
    if (!checkpoint || checkpoint.value().anchor != verified.checkpoint.anchor ||
        checkpoint.value().committed != verified.checkpoint.committed)
      return td::Status::Error("restored index checkpoint differs from verified snapshot");
    TRY_STATUS(db.db_->flush());
  }
  TRY_STATUS(sync_dir(temp));
  TRY_STATUS(check_cancelled(cancelled));
  TRY_RESULT(final_size, file.get_size());
  if (final_size < 0 || static_cast<uint64_t>(final_size) != verified.bytes)
    return td::Status::Error("index snapshot size changed before publication");
  TRY_STATUS(publish(temp, target.string()));
  published = true;
  auto synced = sync_dir(target.parent_path());
  if (synced.is_error())
    return td::Status::Error("index was installed, but parent directory sync failed; durability is unconfirmed: " +
                             synced.message().str());
  return verified;
}

}  // namespace tos_wallet_index
