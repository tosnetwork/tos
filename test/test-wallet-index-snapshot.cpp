/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#include <csignal>
#include <filesystem>
#include <string>
#include <vector>

#if defined(__linux__) || defined(__APPLE__)
#include <sys/resource.h>
#include <sys/stat.h>
#endif

#include "../validator-engine/wallet-index-snapshot.h"
#include "td/db/RocksDb.h"
#include "td/utils/ScopeGuard.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"
#include "td/utils/tests.h"
#include "vm/cells/CellBuilder.h"

namespace {
using namespace tos_wallet_index;
using Rows = std::vector<std::pair<std::string, std::string>>;
namespace fs = std::filesystem;

tos::BlockIdExt master(uint32_t seqno) {
  td::Bits256 root, file;
  root.as_slice().fill(static_cast<char>(seqno));
  file.as_slice().fill(static_cast<char>(seqno + 1));
  return {tos::masterchainId, tos::shardIdAll, seqno, root, file};
}

Rows rows(const std::string& path) {
  auto db = td::RocksDb::open(path).move_as_ok();
  Rows result;
  db.for_each([&](td::Slice key, td::Slice value) {
      result.emplace_back(key.str(), value.str());
      return td::Status::OK();
    }).ensure();
  return result;
}

void append_u32(std::string& out, uint32_t value) {
  for (int i = 3; i >= 0; --i)
    out.push_back(static_cast<char>((value >> (i * 8)) & 255));
}

td::Bits256 digest(td::Slice bytes) {
  td::Bits256 result;
  td::sha256(bytes, result.as_slice());
  return result;
}

std::string encode(const Rows& rows) {
  std::string result("TOSIDX01");
  append_u32(result, kWalletIndexSchemaVersion);
  for (const auto& [key, value] : rows) {
    append_u32(result, static_cast<uint32_t>(key.size()));
    append_u32(result, static_cast<uint32_t>(value.size()));
    result += key;
    result += value;
  }
  result.append(8, '\0');
  return result;
}

struct Fixture {
  std::string dir = td::mkdtemp(td::get_temporary_dir(), "wallet-snapshot-").move_as_ok();
  std::string source = dir + "/source", snapshot = dir + "/snapshot", restored = dir + "/restored";
  Fixture() {
    auto db = WalletIndexDb::open(source).move_as_ok();
    db->initialize_replay(master(1)).ensure();
    db->commit_replay_checkpoint({master(1), master(5)}).ensure();
    db->begin_batch().ensure();
    vm::CellBuilder value;
    value.store_long(123, 32);
    db->put_event(master(2).root_hash, 123, value.finalize()).ensure();
    auto shard = master(6);
    shard.id.workchain = 0;
    db->record_replay_block(shard).ensure();
    db->put_incomplete_block(shard, 6).ensure();
    db->commit_batch().ensure();
  }
  ~Fixture() {
    td::rmrf(dir).ensure();
  }
  bool staging_exists() const {
    for (const auto& entry : fs::directory_iterator(dir))
      if (entry.path().filename().string().find(".wallet-index-import-") == 0)
        return true;
    return false;
  }
  void expect_bad(std::string bytes, const std::string& reason) {
    auto bad = dir + "/bad";
    td::write_file(bad, bytes).ensure();
    auto status = WalletIndexSnapshotFile::restore(bad, restored, digest(bytes));
    ASSERT_TRUE(status.is_error());
    ASSERT_TRUE(status.error().message().str().find(reason) != std::string::npos);
    ASSERT_TRUE(!fs::exists(restored));
    ASSERT_TRUE(!staging_exists());
  }
};
}  // namespace

TEST(WalletIndexSnapshot, RoundTripPreservesEveryRecordAndCheckpoint) {
  Fixture f;
  auto original = rows(f.source);
  auto made = WalletIndexSnapshotFile::create(f.source, f.snapshot).move_as_ok();
  ASSERT_EQ(made.records, original.size());
  auto bytes = td::read_file(f.snapshot).move_as_ok();
  ASSERT_EQ(digest(bytes.as_slice()), made.sha256);
  auto checked = WalletIndexSnapshotFile::verify(f.snapshot, made.sha256).move_as_ok();
  ASSERT_EQ(checked.checkpoint.anchor, master(1));
  ASSERT_EQ(checked.checkpoint.committed, master(5));
  auto restored = WalletIndexSnapshotFile::restore(f.snapshot, f.restored, made.sha256).move_as_ok();
  ASSERT_EQ(restored.sha256, made.sha256);
  ASSERT_TRUE(rows(f.restored) == original);
  ASSERT_TRUE(!f.staging_exists());
  // Replay receipts and unfinished work survive; restore does not manufacture
  // a complete or ready index by deleting recovery/completeness metadata.
  auto db = WalletIndexDb::open(f.restored).move_as_ok();
  auto shard = master(6);
  shard.id.workchain = 0;
  ASSERT_TRUE(db->replay_block_committed(shard).move_as_ok());
  ASSERT_TRUE(db->token_backlog_stats().move_as_ok().unfinished_block);
}

// An untrusted publisher's snapshot needs no digest, but only the account
// history, the schema and the checkpoint enter the new index: receipts,
// unfinished work, token state and every other record are the importing
// node's own to derive. The index starts quarantined.
TEST(WalletIndexSnapshot, UntrustedImportKeepsOnlyHistoryAndQuarantines) {
  Fixture f;
  {
    auto db = WalletIndexDb::open(f.source).move_as_ok();
    db->begin_batch().ensure();
    // A token row the publisher could forge: never imported.
    vm::CellBuilder forged;
    forged.store_long(7, 32);
    db->put_token(master(3).root_hash, master(4).root_hash, forged.finalize()).ensure();
    // A window base and its block's record the publisher could forge: never
    // imported; the importing node writes its own from its blocks.
    tos_wallet_index::WindowBaseRecord base{
        kWalletIndexSchemaVersion,
        master(3),
        {tos_wallet_index::WindowShardTip{tos::ShardIdFull{tos::basechainId, tos::shardIdAll}, 99}}};
    db->put_window_base(3, base).ensure();
    db->commit_batch().ensure();
  }
  auto original = rows(f.source);
  WalletIndexSnapshotFile::create(f.source, f.snapshot).move_as_ok();
  auto imported = WalletIndexSnapshotFile::import_untrusted(f.snapshot, f.restored).move_as_ok();
  ASSERT_EQ(imported.checkpoint.committed, master(5));
  ASSERT_EQ(imported.kept + imported.dropped, original.size());
  ASSERT_TRUE(imported.dropped > 0);
  auto kept = rows(f.restored);
  for (const auto& [key, value] : kept) {
    bool allowed = key == std::string("\0\1", 2) || key == std::string("\0\x20", 2) ||
                   key == std::string("\0\x30", 2) || (key.size() == 41 && key[0] == '\x12');
    ASSERT_TRUE(allowed);
  }
  // The history row, schema, checkpoint and the quarantine mark.
  ASSERT_EQ(kept.size(), imported.kept + 1);
  ASSERT_TRUE(!f.staging_exists());
  auto db = WalletIndexDb::open(f.restored).move_as_ok();
  ASSERT_TRUE(db->get_verification_state().move_as_ok() == VerificationState::Quarantined);
  auto shard = master(6);
  shard.id.workchain = 0;
  ASSERT_TRUE(!db->replay_block_committed(shard).move_as_ok());
  ASSERT_TRUE(!db->token_backlog_stats().move_as_ok().unfinished_block);
  ASSERT_TRUE(db->get_event(master(2).root_hash, 123).is_ok());
  ASSERT_EQ(db->get_window_base().move_as_ok(), 0u);
  ASSERT_TRUE(!db->window_base_record().move_as_ok());
  // A trusted restore keeps the source's state: an index this node built is
  // Full by construction.
  auto made = WalletIndexSnapshotFile::verify(f.snapshot, digest(td::read_file(f.snapshot).move_as_ok().as_slice()));
  ASSERT_TRUE(made.is_ok());
  std::string trusted = f.dir + "/trusted";
  WalletIndexSnapshotFile::restore(f.snapshot, trusted, made.ok().sha256).move_as_ok();
  ASSERT_TRUE(WalletIndexDb::open(trusted).move_as_ok()->get_verification_state().move_as_ok() ==
              VerificationState::Full);
}

// The checkpoint's anchor is authenticated only by an index a node built
// itself, or by a verification that checked it against the node's own first
// block. An untrusted import never carries a publisher's claim of either, and
// re-exporting an imported index, or restoring that export, never turns an
// unverified anchor into an authenticated one.
TEST(WalletIndexSnapshot, AnAnchorIsUnverifiedUntilThisNodeChecksIt) {
  Fixture f;
  int exports = 0;
  auto export_of = [&](const std::string& index) {
    auto file = f.dir + "/export-" + std::to_string(++exports);
    auto made = WalletIndexSnapshotFile::create(index, file).move_as_ok();
    auto checked = WalletIndexSnapshotFile::verify(file, made.sha256).move_as_ok();
    ASSERT_EQ(checked.anchor_verified, made.anchor_verified);
    return std::make_pair(file, made);
  };
  // Built by this node's own replay from block 1.
  auto [own_file, own] = export_of(f.source);
  ASSERT_TRUE(own.anchor_verified);
  // A publisher claims a Full index whose verification checked its anchor.
  {
    auto db = WalletIndexDb::open(f.source).move_as_ok();
    db->begin_batch().ensure();
    WalletIndexDb::VerificationRecord claimed;
    claimed.schema = kWalletIndexSchemaVersion;
    claimed.checkpoint = master(5);
    claimed.anchor_verified = true;
    db->put_verification_record(claimed).ensure();
    db->put_verification_state(VerificationState::Full).ensure();
    db->commit_batch().ensure();
  }
  auto [claimed_file, claimed] = export_of(f.source);
  ASSERT_TRUE(claimed.anchor_verified);
  auto imported = WalletIndexSnapshotFile::import_untrusted(claimed_file, f.restored).move_as_ok();
  ASSERT_TRUE(!imported.anchor_verified);
  // Re-exported before its verification, and restored from that export.
  auto [again_file, again] = export_of(f.restored);
  ASSERT_TRUE(!again.anchor_verified);
  auto trusted = f.dir + "/trusted";
  auto restored = WalletIndexSnapshotFile::restore(again_file, trusted, again.sha256).move_as_ok();
  ASSERT_TRUE(!restored.anchor_verified);
  auto [third_file, third] = export_of(trusted);
  ASSERT_TRUE(!third.anchor_verified);
  // A verification that could not check the anchor keeps it unverified.
  {
    auto db = WalletIndexDb::open(trusted).move_as_ok();
    db->begin_batch().ensure();
    WalletIndexDb::VerificationRecord unchecked;
    unchecked.schema = kWalletIndexSchemaVersion;
    unchecked.checkpoint = master(5);
    db->put_verification_record(unchecked).ensure();
    db->put_verification_state(VerificationState::Partial).ensure();
    db->commit_batch().ensure();
    ASSERT_TRUE(!db->verification_record().move_as_ok().value().anchor_verified);
  }
  auto [partial_file, partial] = export_of(trusted);
  ASSERT_TRUE(!partial.anchor_verified);
}

TEST(WalletIndexSnapshot, UntrustedImportStillRefusesMalformedSnapshots) {
  Fixture f;
  auto bad = f.dir + "/bad";
  // No checkpoint.
  td::write_file(bad, encode({{std::string("\0\1", 2), std::string("\0\0\0\x04", 4)}})).ensure();
  ASSERT_TRUE(WalletIndexSnapshotFile::import_untrusted(bad, f.restored).is_error());
  ASSERT_TRUE(!fs::exists(f.restored));
  ASSERT_TRUE(!f.staging_exists());
}

TEST(WalletIndexSnapshot, VerificationStateRoundTripsAndDefaultsToFull) {
  Fixture f;
  auto db = WalletIndexDb::open(f.source).move_as_ok();
  ASSERT_TRUE(db->get_verification_state().move_as_ok() == VerificationState::Full);
  for (auto state : {VerificationState::Quarantined, VerificationState::Partial, VerificationState::Refused,
                     VerificationState::Full}) {
    db->begin_batch().ensure();
    db->put_verification_state(state).ensure();
    db->commit_batch().ensure();
    ASSERT_TRUE(db->get_verification_state().move_as_ok() == state);
  }
}

TEST(WalletIndexSnapshot, ExportRefusesALiveWriterAndNeverMigratesSchema) {
  Fixture f;
  {
    auto active = WalletIndexDb::open(f.source).move_as_ok();
    auto locked = WalletIndexSnapshotFile::create(f.source, f.snapshot);
    ASSERT_TRUE(locked.is_error());
    ASSERT_TRUE(locked.error().message().str().find("lock") != std::string::npos);
    ASSERT_TRUE(!fs::exists(f.snapshot));
  }
  {
    auto raw = td::RocksDb::open(f.source).move_as_ok();
    raw.set(td::Slice("\0\1", 2), td::Slice("\0\0\0\2", 4)).ensure();
    raw.flush().ensure();
  }
  auto before = rows(f.source);
  auto wrong = WalletIndexSnapshotFile::create(f.source, f.snapshot);
  ASSERT_TRUE(wrong.is_error());
  ASSERT_TRUE(wrong.error().message().str().find("schema") != std::string::npos);
  ASSERT_TRUE(rows(f.source) == before);
  ASSERT_TRUE(!fs::exists(f.snapshot));
}

TEST(WalletIndexSnapshot, TrustedDigestAndDestinationCannotBeBypassed) {
  Fixture f;
  auto made = WalletIndexSnapshotFile::create(f.source, f.snapshot).move_as_ok();
  auto wrong = made.sha256;
  wrong.as_slice()[0] ^= 1;
  auto rejected = WalletIndexSnapshotFile::restore(f.snapshot, f.restored, wrong);
  ASSERT_TRUE(rejected.is_error());
  ASSERT_TRUE(rejected.error().message().str().find("trusted digest") != std::string::npos);
  ASSERT_TRUE(!fs::exists(f.restored));
  ASSERT_TRUE(!f.staging_exists());
  fs::create_directory(f.restored);
  td::write_file(f.restored + "/keep", "untouched").ensure();
  auto exists = WalletIndexSnapshotFile::restore(f.snapshot, f.restored, made.sha256);
  ASSERT_TRUE(exists.is_error());
  ASSERT_TRUE(exists.error().message().str().find("already exists") != std::string::npos);
  ASSERT_EQ(td::read_file(f.restored + "/keep").move_as_ok().as_slice().str(), "untouched");
  ASSERT_TRUE(WalletIndexSnapshotFile::create(f.source, f.snapshot).is_error());
}

TEST(WalletIndexSnapshot, ADestinationCreatedDuringImportIsNeverReplaced) {
  Fixture f;
  auto made = WalletIndexSnapshotFile::create(f.source, f.snapshot).move_as_ok();
  bool raced = false;
  auto rejected = WalletIndexSnapshotFile::restore(f.snapshot, f.restored, made.sha256, [&] {
    if (!raced && f.staging_exists()) {
      ASSERT_TRUE(fs::create_directory(f.restored));
      raced = true;
    }
    return false;
  });
  ASSERT_TRUE(raced);
  ASSERT_TRUE(rejected.is_error());
  ASSERT_TRUE(rejected.error().message().str().find("without replacing destination") != std::string::npos);
  ASSERT_TRUE(fs::is_directory(f.restored));
  ASSERT_TRUE(fs::is_empty(f.restored));
  ASSERT_TRUE(!f.staging_exists());
}

TEST(WalletIndexSnapshot, ParserRejectsAuthenticatedMalformedRecords) {
  Fixture f;
  auto original = rows(f.source);
  auto bytes = encode(original);
  auto wrong_schema = bytes;
  wrong_schema[11] = static_cast<char>(kWalletIndexSchemaVersion + 1);
  f.expect_bad(wrong_schema, "format or schema");
  f.expect_bad(bytes.substr(0, bytes.size() - 1), "truncated");
  f.expect_bad(bytes + "x", "trailing data");
  auto duplicate = original;
  duplicate.insert(duplicate.begin(), duplicate.front());
  f.expect_bad(encode(duplicate), "strictly ordered");
  auto missing = original;
  missing.erase(missing.begin());
  f.expect_bad(encode(missing), "no schema or replay checkpoint");
  auto bad_checkpoint = original;
  for (auto& [key, value] : bad_checkpoint)
    if (key == std::string("\0\x20", 2))
      value[0] = 1;
  f.expect_bad(encode(bad_checkpoint), "invalid replay checkpoint");
  bad_checkpoint = original;
  for (auto& [key, value] : bad_checkpoint)
    if (key == std::string("\0\x20", 2))
      value[5] = 0;
  f.expect_bad(encode(bad_checkpoint), "invalid replay checkpoint identity");
  auto oversized = bytes.substr(0, 12);
  append_u32(oversized, kWalletSnapshotMaxKeyBytes + 1);
  append_u32(oversized, 0);
  f.expect_bad(oversized, "transfer limits");
  oversized = bytes.substr(0, 12);
  append_u32(oversized, 1);
  append_u32(oversized, kWalletSnapshotMaxValueBytes + 1);
  f.expect_bad(oversized, "transfer limits");
}

TEST(WalletIndexSnapshot, BoundsAcceptTheirMaximumAndCancelCleansStaging) {
  Fixture f;
  auto data = rows(f.source);
  data.emplace_back(std::string(kWalletSnapshotMaxKeyBytes, 'z'), std::string(kWalletSnapshotMaxValueBytes, 'v'));
  auto bytes = encode(data);
  auto hash = digest(bytes);
  td::write_file(f.snapshot, bytes).ensure();
  bytes.clear();
  bytes.shrink_to_fit();
  data.clear();
  data.shrink_to_fit();
  ASSERT_TRUE(WalletIndexSnapshotFile::verify(f.snapshot, hash).is_ok());
  bool saw_staging = false;
  auto interrupted = WalletIndexSnapshotFile::restore(f.snapshot, f.restored, hash, [&] {
    saw_staging = f.staging_exists();
    return saw_staging;
  });
  ASSERT_TRUE(saw_staging);
  ASSERT_TRUE(interrupted.is_error());
  ASSERT_TRUE(interrupted.error().message().str().find("interrupted") != std::string::npos);
  ASSERT_TRUE(!fs::exists(f.restored));
  ASSERT_TRUE(!f.staging_exists());
  ASSERT_TRUE(WalletIndexSnapshotFile::restore(f.snapshot, f.restored, hash).is_ok());
  auto raw = td::RocksDb::open(f.restored).move_as_ok();
  std::string value;
  ASSERT_EQ(raw.get(std::string(kWalletSnapshotMaxKeyBytes, 'z'), value).move_as_ok(), td::KeyValue::GetStatus::Ok);
  ASSERT_EQ(value.size(), kWalletSnapshotMaxValueBytes);
}

TEST(WalletIndexSnapshot, BytesChangingAfterVerificationNeverPublish) {
  Fixture f;
  auto made = WalletIndexSnapshotFile::create(f.source, f.snapshot).move_as_ok();
  bool changed = false;
  auto result = WalletIndexSnapshotFile::restore(f.snapshot, f.restored, made.sha256, [&] {
    if (!changed && f.staging_exists()) {
      auto bytes = td::read_file(f.snapshot).move_as_ok().as_slice().str();
      // The last record is a replay receipt with a one-byte value. Preserve
      // framing and checkpoint metadata so the second hash is what refuses it.
      bytes[bytes.size() - 9] ^= 1;
      td::write_file(f.snapshot, bytes).ensure();
      changed = true;
    }
    return false;
  });
  ASSERT_TRUE(changed);
  ASSERT_TRUE(result.is_error());
  ASSERT_TRUE(result.error().message().str().find("trusted digest") != std::string::npos);
  ASSERT_TRUE(!fs::exists(f.restored));
  ASSERT_TRUE(!f.staging_exists());
}

// An untrusted import has no digest to check the second scan against: the
// two scans' hashes must agree, or a same-length change between them would
// be installed.
TEST(WalletIndexSnapshot, BytesChangingDuringAnUntrustedImportNeverPublish) {
  Fixture f;
  WalletIndexSnapshotFile::create(f.source, f.snapshot).move_as_ok();
  bool changed = false;
  auto result = WalletIndexSnapshotFile::import_untrusted(f.snapshot, f.restored, [&] {
    if (!changed && f.staging_exists()) {
      auto bytes = td::read_file(f.snapshot).move_as_ok().as_slice().str();
      bytes[bytes.size() - 9] ^= 1;
      td::write_file(f.snapshot, bytes).ensure();
      changed = true;
    }
    return false;
  });
  ASSERT_TRUE(changed);
  ASSERT_TRUE(result.is_error());
  ASSERT_TRUE(result.error().message().str().find("changed between verification and import") != std::string::npos);
  ASSERT_TRUE(!fs::exists(f.restored));
  ASSERT_TRUE(!f.staging_exists());
}

TEST(WalletIndexSnapshot, AConcurrentAppendCannotExceedTheVerifiedSize) {
  Fixture f;
  auto made = WalletIndexSnapshotFile::create(f.source, f.snapshot).move_as_ok();
  bool changed = false;
  auto result = WalletIndexSnapshotFile::restore(f.snapshot, f.restored, made.sha256, [&] {
    if (!changed && f.staging_exists()) {
      auto file = td::FileFd::open(f.snapshot, td::FileFd::Write | td::FileFd::Append).move_as_ok();
      file.write_all("growing input").ensure();
      changed = true;
    }
    return false;
  });
  ASSERT_TRUE(changed);
  ASSERT_TRUE(result.is_error());
  ASSERT_TRUE(result.error().message().str().find("trailing data") != std::string::npos);
  ASSERT_TRUE(!fs::exists(f.restored));
  ASSERT_TRUE(!f.staging_exists());
}

#if defined(__linux__) || defined(__APPLE__)
TEST(WalletIndexSnapshot, NonRegularInputIsRefusedWithoutBlocking) {
  Fixture f;
  ASSERT_EQ(::mkfifo(f.snapshot.c_str(), 0600), 0);
  auto rejected = WalletIndexSnapshotFile::verify(f.snapshot, td::Bits256::zero());
  ASSERT_TRUE(rejected.is_error());
  ASSERT_TRUE(rejected.error().message().str().find("regular file") != std::string::npos);
}

TEST(WalletIndexSnapshot, AFailedBatchWriteReturnsAnErrorAndRemovesStaging) {
  Fixture f;
  auto records = rows(f.source);
  records.emplace_back("z", std::string(2u << 20, 'v'));
  auto bytes = encode(records);
  td::write_file(f.snapshot, bytes).ensure();
  struct rlimit original;
  ASSERT_EQ(getrlimit(RLIMIT_FSIZE, &original), 0);
  auto original_signal = std::signal(SIGXFSZ, SIG_IGN);
  bool injected = false;
  SCOPE_EXIT {
    ASSERT_EQ(setrlimit(RLIMIT_FSIZE, &original), 0);
    std::signal(SIGXFSZ, original_signal);
  };
  auto failed = WalletIndexSnapshotFile::restore(f.snapshot, f.restored, digest(bytes), [&] {
    if (!injected && f.staging_exists()) {
      // The private DB is open by this point. Refuse its next WAL append,
      // exercising a real RocksDB Write failure, not an earlier open error.
      auto limited = original;
      limited.rlim_cur = 1;
      ASSERT_EQ(setrlimit(RLIMIT_FSIZE, &limited), 0);
      injected = true;
    }
    return false;
  });
  ASSERT_EQ(setrlimit(RLIMIT_FSIZE, &original), 0);
  ASSERT_TRUE(injected);
  ASSERT_TRUE(failed.is_error());
  ASSERT_TRUE(failed.error().message().str().find("File too large") != std::string::npos);
  ASSERT_TRUE(!fs::exists(f.restored));
  ASSERT_TRUE(!f.staging_exists());
}
#endif
