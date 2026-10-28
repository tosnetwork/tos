/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
// A drill tool: prints the vote records of one consensus session journal, one JSON object
// per line, so a drill can tell a replayed signature from a new one by its bytes.
//
//   dump-consensus-journal SESSION_DB_DIR
//
// SESSION_DB_DIR is the RocksDB directory of one session (<db>/consensus/consensus.<..>/db).
// Opening RocksDB writes into its directory, so run this on a copy, never on evidence.
// Each line is one record under consensus.simplex.db.key.vote:
//   {"kind":"cert","vote":"<the vote as the pool logs it>","signatures":[{"who":N,"sha256":"<hex>"},...]}
//   {"kind":"own_signed","vote":"...","signatures":[{"who":-1,"sha256":"<hex>"}]}
//   {"kind":"own_intent","vote":"...","signatures":[]}
// "sha256" is the SHA-256 of the exact signature bytes, and "vote_sha256" that of the
// serialized unsigned vote, so two records name the same signed vote exactly when both match.
// Exit 0 on success, 1 when the journal cannot be read.

#include <cstdio>
#include <string>

#include "auto/tl/tos_api.h"
#include "auto/tl/tos_api.hpp"
#include "consensus/simplex/votes.h"
#include "td/db/RocksDb.h"
#include "td/utils/crypto.h"
#include "td/utils/misc.h"
#include "td/utils/overloaded.h"
#include "tl-utils/tl-utils.hpp"

namespace {

using namespace tos::validator::consensus;

std::string hex_sha256(td::Slice bytes) {
  return td::hex_encode(td::sha256(bytes));
}

std::string json_escape(const std::string& text) {
  std::string out;
  for (char c : text) {
    if (c == '"' || c == '\\') {
      out += '\\';
      out += c;
    } else if (static_cast<unsigned char>(c) < 0x20) {
      out += ' ';
    } else {
      out += c;
    }
  }
  return out;
}

std::string vote_text(const tos::tos_api::consensus_simplex_UnsignedVote& vote) {
  return PSTRING() << simplex::Vote::from_tl(vote);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    std::fprintf(stderr, "usage: %s SESSION_DB_DIR\n", argv[0]);
    return 2;
  }
  auto opened = td::RocksDb::open(argv[1], td::RocksDbOptions{});
  if (opened.is_error()) {
    std::fprintf(stderr, "cannot open %s: %s\n", argv[1], opened.error().to_string().c_str());
    return 1;
  }
  auto db = opened.move_as_ok();
  const td::uint32 prefix = tos::tos_api::consensus_simplex_db_key_vote::ID;
  const td::uint32 next = td::bswap32(td::bswap32(prefix) + 1);
  const td::Slice begin{reinterpret_cast<const char*>(&prefix), 4};
  const td::Slice end{reinterpret_cast<const char*>(&next), 4};
  int records = 0;
  auto status = db.for_each_in_range(begin, end, [&](td::Slice, td::Slice value) -> td::Status {
    auto parsed = tos::fetch_tl_object<tos::tos_api::consensus_simplex_db_Vote>(value, true);
    if (parsed.is_error()) {
      return parsed.move_as_error();
    }
    std::string line;
    tos::tos_api::downcast_call(
        *parsed.ok(),
        td::overloaded(
            [&](tos::tos_api::consensus_simplex_db_cert& record) {
              auto& cert = *record.cert_;
              line = PSTRING() << "{\"kind\":\"cert\",\"vote\":\"" << json_escape(vote_text(*cert.vote_))
                               << "\",\"vote_sha256\":\"" << hex_sha256(tos::serialize_tl_object(cert.vote_, true))
                               << "\",\"signatures\":[";
              bool first = true;
              for (const auto& signature : cert.signatures_->votes_) {
                line += PSTRING() << (first ? "" : ",") << "{\"who\":" << signature->who_ << ",\"sha256\":\""
                                  << hex_sha256(signature->signature_.as_slice()) << "\"}";
                first = false;
              }
              line += "]}";
            },
            [&](tos::tos_api::consensus_simplex_db_ourSignedVote& record) {
              line = PSTRING() << "{\"kind\":\"own_signed\",\"vote\":\"" << json_escape(vote_text(*record.vote_))
                               << "\",\"vote_sha256\":\"" << hex_sha256(tos::serialize_tl_object(record.vote_, true))
                               << "\",\"signatures\":[{\"who\":-1,\"sha256\":\""
                               << hex_sha256(record.signature_.as_slice()) << "\"}]}";
            },
            [&](tos::tos_api::consensus_simplex_db_ourVoteIntent& record) {
              line = PSTRING() << "{\"kind\":\"own_intent\",\"vote\":\"" << json_escape(vote_text(*record.vote_))
                               << "\",\"vote_sha256\":\"" << hex_sha256(tos::serialize_tl_object(record.vote_, true))
                               << "\",\"signatures\":[]}";
            }));
    std::printf("%s\n", line.c_str());
    ++records;
    return td::Status::OK();
  });
  if (status.is_error()) {
    std::fprintf(stderr, "cannot read %s: %s\n", argv[1], status.to_string().c_str());
    return 1;
  }
  std::fprintf(stderr, "%d records\n", records);
  return 0;
}
