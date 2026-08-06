/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    In addition, as a special exception, the copyright holders give permission
    to link the code of portions of this program with the OpenSSL library.
    You must obey the GNU General Public License in all respects for all
    of the code used other than OpenSSL. If you modify file(s) with this
    exception, you may extend this exception to your version of the file(s),
    but you are not obligated to do so. If you do not wish to do so, delete this
    exception statement from your version. If you delete this exception statement
    from all source files in the program, then also delete it here.

    Copyright 2025-2026 TOS Blockchain Teams
*/
// Marker encode/decode coverage for the wc0 wallet index's crash-recovery
// marker (WalletIndexDb::put_incomplete_block / for_each_incomplete_block).
// See doc/node3-residual-leak-archive-memtable-2026-07-26.md for the bugs
// this is regression-testing: a seqno-only marker couldn't distinguish
// blocks at the same seqno in different shards, and a legacy-format marker
// left on disk by an older binary must not crash the new scanner or be
// silently treated as a valid entry.
#include "td/db/RocksDb.h"
#include "td/utils/port/path.h"
#include "td/utils/tests.h"

#include "../validator-engine/wallet-index.h"

#include <set>
#include <string>
#include <vector>

namespace {

tos::BlockIdExt make_test_block_id(tos::WorkchainId workchain, tos::ShardId shard, tos::BlockSeqno seqno,
                                   uint8_t root_fill, uint8_t file_fill) {
  tos::RootHash root_hash;
  tos::FileHash file_hash;
  std::string root_bytes(32, static_cast<char>(root_fill));
  std::string file_bytes(32, static_cast<char>(file_fill));
  root_hash.as_slice().copy_from(td::Slice{root_bytes.data(), root_bytes.size()});
  file_hash.as_slice().copy_from(td::Slice{file_bytes.data(), file_bytes.size()});
  return tos::BlockIdExt{workchain, shard, seqno, root_hash, file_hash};
}

std::unique_ptr<tos_wallet_index::WalletIndexDb> open_fresh_db(const std::string &path) {
  td::rmrf(path).ignore();
  auto r = tos_wallet_index::WalletIndexDb::open(path);
  r.ensure();
  return r.move_as_ok();
}

}  // namespace

TEST(WalletIndex, AccountEventExactLookupAndCursorPagination) {
  auto path = std::string("test-wallet-index-db-events");
  auto db = open_fresh_db(path);
  tos_wallet_index::HashKey account = td::Bits256::zero();
  account.as_slice()[31] = 0x42;
  std::vector<td::Ref<vm::Cell>> cells;
  for (uint64_t lt : {100ULL, 200ULL, 300ULL}) {
    vm::CellBuilder builder;
    builder.store_long(static_cast<long long>(lt), 64);
    cells.push_back(builder.finalize());
    ASSERT_TRUE(db->put_event(account, lt, cells.back()).is_ok());
  }
  auto exact = db->get_event(account, 200);
  ASSERT_TRUE(exact.is_ok());
  ASSERT_TRUE(exact.ok()->get_hash() == cells[1]->get_hash());
  ASSERT_TRUE(db->get_event(account, 201).is_error());

  std::vector<uint64_t> first_page;
  db->for_each_event(account, 2, [&](uint64_t lt, td::Ref<vm::Cell>) {
    first_page.push_back(lt);
    return td::Status::OK();
  }).ensure();
  ASSERT_EQ(first_page, (std::vector<uint64_t>{300, 200}));
  std::vector<uint64_t> second_page;
  db->for_each_event_before(account, 200, 2, [&](uint64_t lt, td::Ref<vm::Cell>) {
    second_page.push_back(lt);
    return td::Status::OK();
  }).ensure();
  ASSERT_EQ(second_page, (std::vector<uint64_t>{100}));
  td::rmrf(path).ignore();
}

TEST(WalletIndex, IncompleteBlockMarkerRoundTrip) {
  auto path = std::string("test-wallet-index-db-roundtrip");
  auto db = open_fresh_db(path);

  auto id = make_test_block_id(0, static_cast<tos::ShardId>(1) << 63, 42, 0xAB, 0xCD);

  ASSERT_TRUE(db->put_incomplete_block(id).is_ok());

  auto has_r = db->has_incomplete_block(id);
  ASSERT_TRUE(has_r.is_ok());
  ASSERT_TRUE(has_r.ok());

  std::vector<tos::BlockIdExt> found;
  auto scan_status = db->for_each_incomplete_block([&](const tos::BlockIdExt &scanned) -> td::Status {
    found.push_back(scanned);
    return td::Status::OK();
  });
  ASSERT_TRUE(scan_status.is_ok());
  ASSERT_EQ(found.size(), static_cast<size_t>(1));
  // Full round trip: workchain, shard, seqno, and both hashes must all
  // survive the encode (put) / decode (for_each) cycle unchanged.
  ASSERT_TRUE(found[0] == id);

  ASSERT_TRUE(db->delete_incomplete_block(id).is_ok());
  auto has_after_r = db->has_incomplete_block(id);
  ASSERT_TRUE(has_after_r.is_ok());
  ASSERT_TRUE(!has_after_r.ok());

  found.clear();
  db->for_each_incomplete_block([&](const tos::BlockIdExt &scanned) -> td::Status {
                        found.push_back(scanned);
                        return td::Status::OK();
                      })
      .ensure();
  ASSERT_TRUE(found.empty());

  td::rmrf(path).ignore();
}

TEST(WalletIndex, IncompleteBlockMarkerDistinguishesSameSeqnoDifferentShard) {
  // Regression test for the bug the full-BlockIdExt marker redesign fixed:
  // a seqno-only marker couldn't tell two different shards' blocks apart,
  // and an ambiguous seqno-only lookup during recovery wasn't guaranteed to
  // resolve back to the right one.
  auto path = std::string("test-wallet-index-db-shard-collision");
  auto db = open_fresh_db(path);

  auto id_a = make_test_block_id(0, 0x2000000000000000ULL, 100, 0x11, 0x22);
  auto id_b = make_test_block_id(0, 0x6000000000000000ULL, 100, 0x33, 0x44);
  ASSERT_TRUE(id_a.id.workchain == id_b.id.workchain);
  ASSERT_TRUE(id_a.id.seqno == id_b.id.seqno);
  ASSERT_TRUE(id_a.id.shard != id_b.id.shard);

  ASSERT_TRUE(db->put_incomplete_block(id_a).is_ok());
  ASSERT_TRUE(db->put_incomplete_block(id_b).is_ok());

  std::set<tos::ShardId> seen_shards;
  int count = 0;
  auto status = db->for_each_incomplete_block([&](const tos::BlockIdExt &scanned) -> td::Status {
    count++;
    seen_shards.insert(scanned.id.shard);
    ASSERT_TRUE(scanned.id.seqno == 100);
    return td::Status::OK();
  });
  ASSERT_TRUE(status.is_ok());
  ASSERT_EQ(count, 2);
  ASSERT_EQ(seen_shards.size(), static_cast<size_t>(2));

  // Deleting one must not touch the other — they are distinct entries, not
  // one seqno-keyed slot two different puts happened to share.
  ASSERT_TRUE(db->delete_incomplete_block(id_a).is_ok());
  auto has_b_r = db->has_incomplete_block(id_b);
  ASSERT_TRUE(has_b_r.is_ok());
  ASSERT_TRUE(has_b_r.ok());

  td::rmrf(path).ignore();
}

TEST(WalletIndex, IncompleteBlockMarkerDistinguishesSamePositionDifferentHash) {
  // If the same (workchain,shard,seqno) position were ever re-applied with a
  // different block hash, the marker must not silently conflate the two —
  // this is why both hashes are part of the key, not just the value.
  auto path = std::string("test-wallet-index-db-hash-collision");
  auto db = open_fresh_db(path);

  auto id_a = make_test_block_id(0, static_cast<tos::ShardId>(1) << 63, 7, 0xAA, 0xAA);
  auto id_b = make_test_block_id(0, static_cast<tos::ShardId>(1) << 63, 7, 0xBB, 0xBB);

  ASSERT_TRUE(db->put_incomplete_block(id_a).is_ok());
  ASSERT_TRUE(db->put_incomplete_block(id_b).is_ok());

  int count = 0;
  db->for_each_incomplete_block([&](const tos::BlockIdExt &) -> td::Status {
                        count++;
                        return td::Status::OK();
                      })
      .ensure();
  ASSERT_EQ(count, 2);

  td::rmrf(path).ignore();
}

TEST(WalletIndex, LegacySeqnoOnlyMarkerNotSurfaced) {
  // A marker written by any binary before the full-BlockIdExt redesign (a
  // bare "0x1E + seqno_be(8)" key, 9 bytes total) must not crash the
  // scanner and must not be handed to the callback as if it were a valid
  // BlockIdExt — see doc/node3-residual-leak-archive-memtable-2026-07-26.md.
  auto path = std::string("test-wallet-index-db-legacy");
  td::rmrf(path).ignore();
  {
    // Write the raw legacy-format key directly, bypassing WalletIndexDb
    // (whose own put_incomplete_block always writes the new format now) to
    // simulate what an older binary left on disk.
    auto raw_r = td::RocksDb::open(path);
    ASSERT_TRUE(raw_r.is_ok());
    auto raw = raw_r.move_as_ok();
    char key[9];
    key[0] = 0x1E;
    uint64_t seqno = 999;
    for (int i = 7; i >= 0; --i) {
      key[1 + i] = static_cast<char>(seqno & 0xff);
      seqno >>= 8;
    }
    char val[1] = {0};
    raw.set(td::Slice{key, 9}, td::Slice{val, 1}).ensure();
  }

  auto db_r = tos_wallet_index::WalletIndexDb::open(path);
  ASSERT_TRUE(db_r.is_ok());
  auto db = db_r.move_as_ok();

  int count = 0;
  auto status = db->for_each_incomplete_block([&](const tos::BlockIdExt &) -> td::Status {
    count++;
    return td::Status::OK();
  });
  ASSERT_TRUE(status.is_ok());
  ASSERT_EQ(count, 0);

  td::rmrf(path).ignore();
}
