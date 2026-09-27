/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// The C++ half of the vote-carrier lock. The Rust half reads the same file, and the
// contracts parse what it describes, so a layout that drifts on any one side produces
// votes the other two refuse -- at the sender's expense, since the message is paid for
// before it is read.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "crypto/block/pq-vote.h"
#include "crypto/pq/mldsa44.h"
#include "td/utils/misc.h"
#include "vm/boc.h"
#include "vm/cellslice.h"

namespace {

td::Bits256 fill(unsigned char b) {
  td::Bits256 out;
  std::memset(out.data(), b, 32);
  return out;
}

std::string pattern_signature() {
  std::string out(tos::pq::mldsa44_signature_bytes, '\0');
  for (std::size_t i = 0; i < out.size(); i++) {
    out[i] = static_cast<char>(i % 251);
  }
  return out;
}

std::vector<std::string> split(const std::string& line, char sep) {
  std::vector<std::string> out;
  std::istringstream row(line);
  for (std::string field; std::getline(row, field, sep);) {
    out.push_back(field);
  }
  return out;
}

struct Recorded {
  std::string root_hash;
  std::string boc_hex;
};

}  // namespace

int main() {
  std::map<std::string, Recorded> recorded;
  {
    std::ifstream file(VOTE_CARRIER_VECTORS_FILE);
    assert(file);
    for (std::string line; std::getline(file, line);) {
      if (line.empty() || line[0] == '#') {
        continue;
      }
      auto fields = split(line, '\t');
      assert(fields.size() == 3);
      recorded[fields[0]] = Recorded{fields[1], fields[2]};
    }
  }
  assert(!recorded.empty());

  const auto signature = pattern_signature();
  const td::uint64 query = 0x1234567890abcdefULL;

  std::map<std::string, td::Ref<vm::Cell>> built;
  auto build = [&](const char* name, td::Result<td::Ref<vm::Cell>> body) {
    assert(body.is_ok());
    built[name] = body.move_as_ok();
  };
  build("config-vote", block::pq::config_vote_body(query, 7, fill(0xe5), signature));
  build("complaint-vote", block::pq::complaint_vote_body(query, 7, 1789434000u, fill(0xf6), signature));
  build("config-vote-other-query", block::pq::config_vote_body(query - 1, 7, fill(0xe5), signature));
  build("config-vote-other-index", block::pq::config_vote_body(query, 8, fill(0xe5), signature));
  build("config-vote-other-proposal", block::pq::config_vote_body(query, 7, fill(0xe6), signature));
  build("complaint-vote-other-index", block::pq::complaint_vote_body(query, 8, 1789434000u, fill(0xf6), signature));
  build("complaint-vote-other-election", block::pq::complaint_vote_body(query, 7, 1789434001u, fill(0xf6), signature));
  build("complaint-vote-other-complaint", block::pq::complaint_vote_body(query, 7, 1789434000u, fill(0xf7), signature));

  // Every recorded row is built, and every built row is recorded. A row nobody claims is
  // a layout nobody checks; a claim with no row is a test that silently stopped covering
  // something.
  for (const auto& [name, _] : recorded) {
    if (built.find(name) == built.end()) {
      std::printf("the file records %s and nothing builds it\n", name.c_str());
      assert(false);
    }
  }
  for (const auto& [name, _] : built) {
    if (recorded.find(name) == recorded.end()) {
      std::printf("%s is built and the file does not record it\n", name.c_str());
      assert(false);
    }
  }

  // The bytes, not only the hash: a recorded hash with a different serialisation beside
  // it would pass a hash comparison and hand the Rust side a different message.
  for (const auto& [name, cell] : built) {
    const auto& want = recorded.at(name);
    const auto hash = cell->get_hash().to_hex();
    if (hash != want.root_hash) {
      std::printf("%s: recorded %s, built %s\n", name.c_str(), want.root_hash.c_str(), hash.c_str());
      assert(false);
    }
    auto boc = vm::std_boc_serialize(cell, 2).move_as_ok();
    const auto encoded = td::hex_encode(boc.as_slice());
    if (encoded != want.boc_hex) {
      std::printf("%s: the serialisation differs from the recorded one\n", name.c_str());
      assert(false);
    }
    auto back = vm::std_boc_deserialize(td::hex_decode(want.boc_hex).move_as_ok());
    assert(back.is_ok());
    assert(back.move_as_ok()->get_hash() == cell->get_hash());
  }

  // The same carriers as the operator tooling serialises them. The two libraries frame a
  // bag of cells differently, so these are not the bytes above; what matters is that the
  // node can read what the tooling sends and reach the same message. Without this the
  // direction that carries a real vote -- tooling writes, node reads -- is the one
  // direction nothing tries.
  {
    std::map<std::string, std::string> from_tooling;
    std::ifstream file(VOTE_CARRIER_TOOLING_FILE);
    assert(file);
    for (std::string line; std::getline(file, line);) {
      if (line.empty() || line[0] == '#') {
        continue;
      }
      auto fields = split(line, '\t');
      assert(fields.size() == 2);
      from_tooling[fields[0]] = fields[1];
    }
    if (from_tooling.size() != built.size()) {
      std::printf("the tooling recorded %zu carriers and this side builds %zu\n", from_tooling.size(), built.size());
      assert(false);
    }
    for (const auto& [name, cell] : built) {
      auto found = from_tooling.find(name);
      if (found == from_tooling.end()) {
        std::printf("the tooling did not record %s\n", name.c_str());
        assert(false);
      }
      auto bytes = td::hex_decode(found->second);
      assert(bytes.is_ok());
      auto read_back = vm::std_boc_deserialize(bytes.move_as_ok());
      if (read_back.is_error()) {
        std::printf("%s: this side cannot read what the tooling writes\n", name.c_str());
        assert(false);
      }
      if (read_back.move_as_ok()->get_hash() != cell->get_hash()) {
        std::printf("%s: what the tooling writes is a different message\n", name.c_str());
        assert(false);
      }
    }
  }

  // Each "other" row differs from its base in one field, so every one of them must be a
  // different message. A layout that dropped a field would make two of these equal.
  std::set<std::string> distinct;
  for (const auto& [name, cell] : built) {
    distinct.insert(cell->get_hash().to_hex());
  }
  if (distinct.size() != built.size()) {
    std::printf("two of the %zu carriers are the same message\n", built.size());
    assert(false);
  }

  // The base rows, read back field by field. The recorded hash says the bytes have not
  // moved; this says what they mean.
  {
    vm::CellSlice cs{vm::NoVm(), built.at("config-vote")};
    assert(cs.fetch_ulong(32) == tos::pq::config_pq_vote_op);
    assert(cs.fetch_ulong(64) == query);
    assert(cs.fetch_ulong(16) == 7);
    td::Bits256 subject;
    assert(cs.fetch_bits_to(subject.bits(), 256));
    assert(subject == fill(0xe5));
    assert(cs.size() == 0 && cs.size_refs() == 1);
  }
  {
    vm::CellSlice cs{vm::NoVm(), built.at("complaint-vote")};
    assert(cs.fetch_ulong(32) == tos::pq::elector_pq_complaint_op);
    assert(cs.fetch_ulong(64) == query);
    assert(cs.fetch_ulong(16) == 7);
    assert(cs.fetch_ulong(32) == 1789434000u);
    td::Bits256 subject;
    assert(cs.fetch_bits_to(subject.bits(), 256));
    assert(subject == fill(0xf6));
    assert(cs.size() == 0 && cs.size_refs() == 1);
  }

  // A count the file and the builders have to agree on, stated rather than inferred: two
  // rows named the same would otherwise leave one of them unbuilt and unnoticed.
  constexpr std::size_t expected = 8;
  if (built.size() != expected || recorded.size() != expected) {
    std::printf("expected %zu carriers, built %zu, recorded %zu\n", expected, built.size(), recorded.size());
    assert(false);
  }

  std::printf(
      "VOTE_CARRIER_OK %zu vote carriers match the recorded bytes, are readable as the tooling writes "
      "them, and no two are the same\n",
      built.size());
  return 0;
}
