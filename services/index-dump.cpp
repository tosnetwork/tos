/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
// Print the content of a stopped wallet index (opened read-only).
//
// Raw (default): one line per key in key order, "<key hex> <sha256 of value
// hex>", then "keys=<n> sha256=<digest of those lines>", for comparing two
// replays of the same source byte for byte.
//
// --canonical: what the index serves over its window, for comparing indexes
// built different ways (replayed, imported and verified, built from the
// window's blocks): the schema, the checkpoint and the window base with their
// full identities, then each account's served history, the current token
// entries and the NFT entries, the verdict lts they embed left out (see
// tos_wallet_index::for_each_canonical_line), then "sha256=<digest of every
// line above>". The anchor's verification status is printed after the
// digest, outside it. --head must be the checkpoint's masterchain seqno.
// --window-base-from takes the window base and its record from another
// stopped index at the same checkpoint, to compare over that index's window;
// it may only narrow this index's window.
#include <iostream>
#include <string>

#include "td/db/RocksDbReadOnly.h"
#include "td/utils/OptionParser.h"
#include "td/utils/Slice.h"
#include "td/utils/crypto.h"
#include "td/utils/misc.h"
#include "validator-engine/wallet-index.h"

namespace {
using tos_wallet_index::HistoryWindow;
using tos_wallet_index::WalletIndexDb;

int raw_dump(td::KeyValue& db) {
  td::Sha256State total;
  total.init();
  uint64_t keys = 0;
  auto status = db.for_each([&](td::Slice key, td::Slice value) {
    unsigned char value_hash[32];
    td::sha256(value, td::MutableSlice(value_hash, 32));
    auto line = td::hex_encode(key) + " " + td::hex_encode(td::Slice(value_hash, 32)) + "\n";
    total.feed(line);
    std::cout << line;
    ++keys;
    return td::Status::OK();
  });
  if (status.is_error()) {
    std::cerr << "iteration failed: " << status.message().str() << std::endl;
    return 1;
  }
  unsigned char digest[32];
  total.extract(td::MutableSlice(digest, 32));
  std::cout << "keys=" << keys << " sha256=" << td::hex_encode(td::Slice(digest, 32)) << std::endl;
  return 0;
}

// What a canonical dump is bound to: the schema, the checkpoint.
struct Bound {
  uint32_t schema = 0;
  WalletIndexDb::ReplayCheckpoint checkpoint;
};

td::Result<Bound> read_bound(td::KeyValue& db) {
  Bound bound;
  std::string value;
  TRY_RESULT(schema, db.get(td::Slice("\0\1", 2), value));
  if (schema != td::KeyValue::GetStatus::Ok || value.size() != 4) {
    return td::Status::Error("no schema version");
  }
  bound.schema = (static_cast<uint8_t>(value[0]) << 24) | (static_cast<uint8_t>(value[1]) << 16) |
                 (static_cast<uint8_t>(value[2]) << 8) | static_cast<uint8_t>(value[3]);
  if (bound.schema != tos_wallet_index::kWalletIndexSchemaVersion) {
    return td::Status::Error(PSTRING() << "schema " << bound.schema << " is not "
                                       << tos_wallet_index::kWalletIndexSchemaVersion);
  }
  TRY_RESULT(found, db.get(td::Slice("\0\x20", 2), value));
  if (found != td::KeyValue::GetStatus::Ok) {
    return td::Status::Error("no replay checkpoint");
  }
  TRY_RESULT_ASSIGN(bound.checkpoint, WalletIndexDb::parse_replay_checkpoint(value));
  return bound;
}

// Whether the checkpoint's anchor was checked against the node's own block
// 1 (the verification record's flag); "unrecorded" without a record.
std::string anchor_status(td::KeyValue& db) {
  std::string value;
  auto found = db.get(td::Slice("\0\x31", 2), value);
  if (found.is_error() || found.ok() != td::KeyValue::GetStatus::Ok) {
    return "unrecorded";
  }
  auto record = WalletIndexDb::parse_verification_record(value);
  if (record.is_error()) {
    return "malformed";
  }
  return record.ok().anchor_verified ? "yes" : "no";
}

int canonical_dump(td::KeyValue& db, uint32_t head, const std::string& base_from) {
  auto bound = read_bound(db);
  if (bound.is_error()) {
    std::cerr << "not a canonical index: " << bound.error().message().str() << std::endl;
    return 2;
  }
  const auto& committed = bound.ok().checkpoint.committed;
  if (committed.seqno() != head) {
    std::cerr << "the index's checkpoint is masterchain block " << committed.seqno() << ", not " << head << std::endl;
    return 2;
  }
  auto own = tos_wallet_index::read_history_window(db);
  if (own.is_error()) {
    std::cerr << own.error().message().str() << std::endl;
    return 2;
  }
  HistoryWindow window = own.move_as_ok();
  if (!base_from.empty()) {
    auto other_db = td::RocksDbReadOnly::open(base_from);
    if (other_db.is_error()) {
      std::cerr << "cannot open " << base_from << " read-only: " << other_db.error().message().str() << std::endl;
      return 2;
    }
    auto other_bound = read_bound(other_db.ok_ref());
    if (other_bound.is_error() || other_bound.ok().schema != bound.ok().schema ||
        other_bound.ok().checkpoint.committed != committed) {
      std::cerr << "the other index is not at this index's checkpoint, with its schema" << std::endl;
      return 2;
    }
    auto other = tos_wallet_index::read_history_window(other_db.ok_ref());
    if (other.is_error()) {
      std::cerr << "the other index's window: " << other.error().message().str() << std::endl;
      return 2;
    }
    if (other.ok().base < window.base || other.ok().base > head) {
      std::cerr << "the other index's window base " << other.ok().base << " is not within [" << window.base << ", "
                << head << "]: the window may only narrow" << std::endl;
      return 2;
    }
    window = other.move_as_ok();
  }
  td::Sha256State total;
  total.init();
  auto emit = [&](const std::string& line) {
    total.feed(line);
    total.feed("\n");
    std::cout << line << "\n";
    return td::Status::OK();
  };
  emit(PSTRING() << "schema=" << bound.ok().schema).ensure();
  emit(PSTRING() << "checkpoint=" << bound.ok().checkpoint.anchor.to_str() << " " << committed.to_str()).ensure();
  emit(PSTRING() << "head=" << head).ensure();
  emit(PSTRING() << "window_base=" << window.base).ensure();
  emit(PSTRING() << "window_base_block=" << (window.record ? window.record.value().block.to_str() : "none")).ensure();
  auto status = tos_wallet_index::for_each_canonical_line(db, window, emit);
  if (status.is_error()) {
    std::cerr << "canonical scan failed: " << status.message().str() << std::endl;
    return 1;
  }
  unsigned char digest[32];
  total.extract(td::MutableSlice(digest, 32));
  std::cout << "sha256=" << td::hex_encode(td::Slice(digest, 32)) << "\n";
  std::cout << "anchor_verified=" << anchor_status(db) << std::endl;
  return 0;
}
}  // namespace

int main(int argc, char** argv) {
  std::string path, base_from;
  bool canonical = false;
  td::optional<uint32_t> head;
  td::OptionParser parser;
  parser.set_description("Print the content of a stopped wallet index (read-only).");
  parser.add_option('\0', "index-dir", "the index directory, <data-dir>/index", [&](td::Slice v) { path = v.str(); });
  parser.add_option('\0', "canonical", "print the canonical view over the index's window and its digest",
                    [&] { canonical = true; });
  parser.add_checked_option('\0', "head", "the checkpoint's masterchain seqno (--canonical)",
                            [&](td::Slice v) -> td::Status {
                              TRY_RESULT(seqno, td::to_integer_safe<uint32_t>(v));
                              head = seqno;
                              return td::Status::OK();
                            });
  parser.add_option('\0', "window-base-from",
                    "another stopped index at the same checkpoint whose window base to use (--canonical)",
                    [&](td::Slice v) { base_from = v.str(); });
  auto parsed = parser.run(argc, argv);
  if (parsed.is_error() || path.empty() || (canonical && !head) || (!canonical && (head || !base_from.empty()))) {
    std::cerr << "specify --index-dir, and with --canonical also --head" << std::endl;
    return 2;
  }
  auto db = td::RocksDbReadOnly::open(path);
  if (db.is_error()) {
    std::cerr << "cannot open " << path << " read-only: " << db.error().message().str() << std::endl;
    return 2;
  }
  return canonical ? canonical_dump(db.ok_ref(), head.value(), base_from) : raw_dump(db.ok_ref());
}
