/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#ifdef NDEBUG
#undef NDEBUG  // test assertions must stay live even in Release (-DNDEBUG)
#endif
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <keys/keys.hpp>
#include <map>
#include <string>
#include <type_traits>
#include <vector>

#include "auto/tl/tos_api.hpp"
#include "block/block-auto.h"
#include "block/block.h"
#include "block/mc-config.h"
#include "block/validator-session-members.h"
#include "block/validator-set.h"
#include "crypto/pq/pq-bytes.h"
#include "crypto/pq/pq-consensus.h"
#include "crypto/pq/pq-elector.h"
#include "td/utils/misc.h"
#include "tl-utils/tl-utils.hpp"
#include "vm/cells/CellBuilder.h"
#include "vm/dict.h"

namespace {

td::Bits256 fill(unsigned char b) {
  td::Bits256 out;
  std::memset(out.data(), b, 32);
  return out;
}

td::Bits256 key_id_of(const std::string& public_key) {
  auto derived = tos::pq::derive_key_id(tos::pq::PQAlgorithmId::mldsa44, public_key);
  assert(derived.has_value());
  td::Bits256 out;
  std::memcpy(out.data(), derived->data(), derived->size());
  return out;
}

// One post-quantum descriptor, with every field under the caller's control so a single
// rule can be broken at a time and nothing else.
td::Ref<vm::Cell> pq_descriptor(const td::Bits256& validator_id, int algorithm_id, const td::Bits256& key_id,
                                const std::string& public_key, td::uint64 weight, const td::Bits256& adnl_addr) {
  vm::CellBuilder cb;
  cb.store_long(0xb3, 8);
  cb.store_bits_bool(validator_id.cbits(), 256);
  cb.store_long(algorithm_id, 16);
  cb.store_bits_bool(key_id.cbits(), 256);
  cb.store_ref(tos::pq::pack_pq_bytes(td::Slice(public_key), tos::pq::pq_bytes_hard_max).move_as_ok());
  cb.store_long(static_cast<long long>(weight), 64);
  cb.store_bits_bool(adnl_addr.cbits(), 256);
  return cb.finalize();
}

// A validators_ext#12 set around the given descriptors.
td::Ref<vm::Cell> validator_set_cell(const std::vector<td::Ref<vm::Cell>>& descriptors, td::uint64 total_weight) {
  vm::Dictionary dict{16};
  for (std::size_t i = 0; i < descriptors.size(); i++) {
    td::BitArray<16> key;
    key.store_ulong(i);
    auto cs = vm::load_cell_slice_ref(descriptors[i]);
    bool ok = dict.set(key.cbits(), 16, cs);
    assert(ok);
  }
  vm::CellBuilder cb;
  cb.store_long(0x12, 8);                                         // validators_ext#12
  cb.store_long(100, 32);                                         // utime_since
  cb.store_long(200, 32);                                         // utime_until
  cb.store_long(static_cast<long long>(descriptors.size()), 16);  // total
  cb.store_long(static_cast<long long>(descriptors.size()), 16);  // main
  cb.store_long(static_cast<long long>(total_weight), 64);        // total_weight
  cb.store_maybe_ref(dict.get_root_cell());                       // list
  return cb.finalize();
}

}  // namespace

int main() {
  const std::string key_a(tos::pq::mldsa44_public_key_bytes, '\x11');
  const std::string key_b(tos::pq::mldsa44_public_key_bytes, '\x22');
  const auto vid = fill(0xa0);
  const auto adnl = fill(0xc0);
  const auto kid_a = key_id_of(key_a), kid_b = key_id_of(key_b);
  assert(kid_a != kid_b);  // different keys really do have different identities

  // The same validator, before and after rotating its consensus key.
  auto before =
      block::Config::unpack_validator_set(validator_set_cell({pq_descriptor(vid, 1, kid_a, key_a, 5, adnl)}, 5), false)
          .move_as_ok();
  auto after =
      block::Config::unpack_validator_set(validator_set_cell({pq_descriptor(vid, 1, kid_b, key_b, 5, adnl)}, 5), false)
          .move_as_ok();

  block::ValidatorSet set_before{1, tos::ShardIdFull{tos::masterchainId}, before->export_validator_set()};
  block::ValidatorSet set_after{1, tos::ShardIdFull{tos::masterchainId}, after->export_validator_set()};

  // Membership is by the stable identity, so rotation does not move the validator in or
  // out of the set. This is the whole point of keeping the two identities apart.
  assert(set_before.is_validator(tos::ValidatorId{vid}));
  assert(set_after.is_validator(tos::ValidatorId{vid}));

  // The consensus key identity did change, and it is tracked separately.
  assert(set_before.get_validator_by_key_id(tos::ConsensusKeyId{kid_a}) != nullptr);
  assert(set_before.get_validator_by_key_id(tos::ConsensusKeyId{kid_b}) == nullptr);
  assert(set_after.get_validator_by_key_id(tos::ConsensusKeyId{kid_b}) != nullptr);
  assert(set_after.get_validator_by_key_id(tos::ConsensusKeyId{kid_a}) == nullptr);

  // The descriptor really carries the rotated key, not a stale one.
  assert(set_before.get_validator(tos::ValidatorId{vid})->pq_public_key == key_a);
  assert(set_after.get_validator(tos::ValidatorId{vid})->pq_public_key == key_b);
  assert(set_after.get_validator(tos::ValidatorId{vid})->is_pq());

  // An ADNL address is not a membership identity. It is a distinct type at compile time,
  // so the only way to ask with it is to say so explicitly -- and it finds nothing.
  assert(!set_after.is_validator(tos::ValidatorId{adnl}));

  // A descriptor may not claim a key identity its key does not derive.
  assert(
      block::Config::unpack_validator_set(validator_set_cell({pq_descriptor(vid, 1, kid_a, key_b, 5, adnl)}, 5), false)
          .is_error());
  // An unknown algorithm and a wrong-length key are both refused by the derivation
  // itself, which yields nothing rather than an identity. The diagnosis is asserted
  // because that is this guard's whole contribution: without it the code would go on to
  // read an identity that was never produced.
  auto unknown_alg =
      block::Config::unpack_validator_set(validator_set_cell({pq_descriptor(vid, 7, kid_a, key_a, 5, adnl)}, 5), false);
  assert(unknown_alg.is_error());
  assert(unknown_alg.error().message().str().find("unknown consensus algorithm") != std::string::npos);
  const std::string short_key(tos::pq::mldsa44_public_key_bytes - 1, '\x11');
  auto short_key_set = block::Config::unpack_validator_set(
      validator_set_cell({pq_descriptor(vid, 1, key_id_of(key_a), short_key, 5, adnl)}, 5), false);
  assert(short_key_set.is_error());
  assert(short_key_set.error().message().str().find("unknown consensus algorithm") != std::string::npos);
  assert(block::Config::unpack_validator_set(validator_set_cell({pq_descriptor(vid, 1, kid_a, key_a, 5, fill(0))}, 5),
                                             false)
             .is_error());
  assert(block::Config::unpack_validator_set(validator_set_cell({pq_descriptor(fill(0), 1, kid_a, key_a, 5, adnl)}, 5),
                                             false)
             .is_error());

  {  // Every structural rule gets an input that is valid apart from the one thing it
     // breaks, so nothing can pass for the wrong reason. Uniqueness is refused when the
     // set is decoded, not by aborting later.
    const auto key_c = std::string(tos::pq::mldsa44_public_key_bytes, '\x33');
    const auto kid_c = key_id_of(key_c);
    auto ok = [&](const std::vector<td::Ref<vm::Cell>>& d, td::uint64 w) {
      return block::Config::unpack_validator_set(validator_set_cell(d, w), false);
    };
    // the two-member baseline every case below is a single change away from
    assert(ok({pq_descriptor(vid, 1, kid_a, key_a, 5, adnl), pq_descriptor(fill(0xa5), 1, kid_c, key_c, 7, fill(0xc5))},
              12)
               .is_ok());

    // one validator appearing twice, under two different keys
    assert(ok({pq_descriptor(vid, 1, kid_a, key_a, 5, adnl), pq_descriptor(vid, 1, kid_c, key_c, 7, fill(0xc5))}, 12)
               .is_error());
    // two validators sharing one consensus key
    assert(ok({pq_descriptor(vid, 1, kid_a, key_a, 5, adnl), pq_descriptor(fill(0xa5), 1, kid_a, key_a, 7, fill(0xc5))},
              12)
               .is_error());
    // the same public key twice, which is refused because a key identity is bound to
    // the key that produces it, so a repeated key is a repeated identity
    assert(ok({pq_descriptor(vid, 1, kid_a, key_a, 5, adnl),
               pq_descriptor(fill(0xa5), 1, key_id_of(key_a), key_a, 7, fill(0xc5))},
              12)
               .is_error());
    // A member with no stake at all. The weight accumulator refuses this too, so what
    // is checked here is the diagnosis: reported as a zero weight, not as exceeding the
    // protocol cap, which would send an operator looking in the wrong place.
    auto zero_weight = ok(
        {pq_descriptor(vid, 1, kid_a, key_a, 5, adnl), pq_descriptor(fill(0xa5), 1, kid_c, key_c, 0, fill(0xc5))}, 5);
    assert(zero_weight.is_error());
    assert(zero_weight.error().message().str().find("zero weight") != std::string::npos);
    // a declared total that does not match what the members add up to
    assert(ok({pq_descriptor(vid, 1, kid_a, key_a, 5, adnl)}, 6).is_error());
    // weights that would overflow the accumulator the quorum maths depends on
    assert(ok({pq_descriptor(vid, 1, kid_a, key_a, 0xffffffffffffffffULL, adnl),
               pq_descriptor(fill(0xa5), 1, kid_c, key_c, 0xffffffffffffffffULL, fill(0xc5))},
              0)
               .is_error());
  }

  {  // The recorded version 2 commitment vectors must still be what this code produces.
    std::ifstream f(SET_HASH_VECTORS_FILE);
    assert(f);
    std::string line;
    int seen = 0;
    while (std::getline(f, line)) {
      if (line.empty()) {
        continue;
      }
      std::vector<std::string> field;
      for (std::size_t p = 0, q; p <= line.size(); p = q + 1) {
        q = line.find(' ', p);
        if (q == std::string::npos) {
          q = line.size();
        }
        field.push_back(line.substr(p, q - p));
      }
      assert(field.size() == 5);
      const auto cc_seqno = static_cast<tos::CatchainSeqno>(std::stoul(field[1]));
      std::vector<tos::ValidatorDescr> nodes;
      for (std::size_t p = 0, q; p <= field[2].size(); p = q + 1) {
        q = field[2].find(';', p);
        if (q == std::string::npos) {
          q = field[2].size();
        }
        auto entry = field[2].substr(p, q - p);
        std::vector<std::string> part;
        for (std::size_t a = 0, b; a <= entry.size(); a = b + 1) {
          b = entry.find(':', a);
          if (b == std::string::npos) {
            b = entry.size();
          }
          part.push_back(entry.substr(a, b - a));
        }
        assert(part.size() == 4);
        td::Bits256 vid, kid, adnl;
        std::memcpy(vid.data(), td::hex_decode(part[0]).move_as_ok().data(), 32);
        std::memcpy(kid.data(), td::hex_decode(part[1]).move_as_ok().data(), 32);
        std::memcpy(adnl.data(), td::hex_decode(part[3]).move_as_ok().data(), 32);
        nodes.push_back(tos::ValidatorDescr{tos::ValidatorId{vid}, 1, tos::ConsensusKeyId{kid},
                                            std::string(tos::pq::mldsa44_public_key_bytes, '\x01'),
                                            std::stoull(part[2]), adnl});
      }
      assert(td::hex_encode(td::Slice(block::validator_set_hash_preimage(cc_seqno, nodes))) == field[3]);
      char got[16];
      std::snprintf(got, sizeof got, "%08x",
                    block::compute_validator_set_hash(cc_seqno, tos::ShardIdFull{tos::masterchainId}, nodes));
      assert(std::string(got) == field[4]);
      seen++;
    }
    assert(seen >= 5);
  }

  {  // A block is attributed to a producer by stable identity, not by key.
     //
     // "Not a key alias" is a property of the types, so it is checked as one: if a
     // conversion existed in either direction, the old habit of passing a key where an
     // identity belongs would compile again and nothing would notice.
    static_assert(!std::is_constructible_v<tos::ValidatorId, tos::Ed25519_PublicKey>,
                  "a validator identity must not be constructible from a key");
    static_assert(!std::is_constructible_v<tos::Ed25519_PublicKey, tos::ValidatorId>,
                  "a key must not be constructible from a validator identity");
    static_assert(std::is_same_v<decltype(tos::BlockCandidate::producer), tos::ValidatorId>,
                  "a candidate's producer must be an identity, not a key");

    // The identity a block would be attributed to comes from the descriptor, so it is
    // the same validator before and after its consensus key changes, while the key
    // identity moves with the key.
    const auto* before_descr = set_before.get_validator(tos::ValidatorId{vid});
    const auto* after_descr = set_after.get_validator(tos::ValidatorId{vid});
    assert(before_descr != nullptr && after_descr != nullptr);
    assert(before_descr->validator_id == after_descr->validator_id);
    assert(before_descr->key_id != after_descr->key_id);
  }

  {  // A consensus session must commit to both identities, so that rotating a key
     // starts a different session while the validator stays the same member.
    auto session_id = [](const std::vector<tos::ValidatorDescr>& nodes) {
      return tos::create_hash_tl_object<tos::tos_api::validator_groupNew>(
          0, static_cast<long long>(0x8000000000000000ull), 0, 0, 1, td::Bits256::zero(),
          block::validator_session_members(nodes));
    };
    auto pq_node = [](const td::Bits256& vid, const td::Bits256& kid) {
      return tos::ValidatorDescr{tos::ValidatorId{vid},
                                 1,
                                 tos::ConsensusKeyId{kid},
                                 std::string(tos::pq::mldsa44_public_key_bytes, '\x01'),
                                 5,
                                 fill(0xc0)};
    };
    const auto vid_x = fill(0xa0), vid_y = fill(0xa1);
    const auto kid_1 = fill(0xb0), kid_2 = fill(0xb1);

    // the same validator, before and after rotating its key
    assert(session_id({pq_node(vid_x, kid_1)}) != session_id({pq_node(vid_x, kid_2)}));
    // the same key, held by a different validator
    assert(session_id({pq_node(vid_x, kid_1)}) != session_id({pq_node(vid_y, kid_1)}));
    // and the identical member is of course the identical session
    assert(session_id({pq_node(vid_x, kid_1)}) == session_id({pq_node(vid_x, kid_1)}));

    // A classical member and a post-quantum member are distinct constructors of one
    // boxed type, so their encodings cannot be mistaken for one another.
    auto classical = tos::ValidatorDescr{tos::Ed25519_PublicKey{fill(0x11)}, 5, fill(0xc0)};
    auto pq_members = block::validator_session_members({pq_node(vid_x, kid_1)});
    auto classical_members = block::validator_session_members({classical});
    assert(pq_members[0]->get_id() != classical_members[0]->get_id());
    assert(pq_members[0]->get_id() == tos::tos_api::validator_groupMemberPQ::ID);
    assert(classical_members[0]->get_id() == tos::tos_api::validator_groupMember::ID);
    // a classical member still reports the identity derived from its key
    assert(session_id({classical}) != session_id({pq_node(vid_x, kid_1)}));
  }

  {  // The shared verdicts: both implementations read these exact encoded sets and must
     // agree on every one of them.
    std::ifstream f(SET_CASES_FILE);
    assert(f);
    std::string line;
    int seen = 0;
    while (std::getline(f, line)) {
      if (line.empty()) {
        continue;
      }
      auto a = line.find(' '), b = line.find(' ', a + 1);
      assert(a != std::string::npos && b != std::string::npos);
      const auto name = line.substr(0, a);
      const auto verdict = line.substr(a + 1, b - a - 1);
      auto boc = td::hex_decode(line.substr(b + 1)).move_as_ok();
      auto set = vm::std_boc_deserialize(boc).move_as_ok();
      const bool accepted = block::Config::unpack_validator_set(set, false).is_ok();
      assert(accepted == (verdict == "accept"));
      seen++;
    }
    assert(seen >= 14);
  }

  {  // Several 32-byte values meet on one validator, and substituting one for another is
     // the mistake this whole phase is about. The ones that are required to differ are
     // deliberately distinct here, because a test written where two of them happened to
     // coincide would keep passing after exactly that substitution. Note that a
     // classical validator's membership identity and key identity are the same value by
     // design; only a post-quantum one separates them.
    auto classical = tos::ValidatorDescr{tos::Ed25519_PublicKey{fill(0x11)}, 5, fill(0xc0)};
    block::ValidatorSet classical_set{1, tos::ShardIdFull{tos::masterchainId}, {classical}};
    const auto* c = classical_set.get_validator(tos::ValidatorId{
        tos::PublicKey{tos::pubkeys::Ed25519{tos::Ed25519_PublicKey{fill(0x11)}}}.compute_short_id().bits256_value()});
    assert(c != nullptr);

    const auto raw_key = fill(0x11);              // the Ed25519 key itself
    const auto short_id = c->validator_id.value;  // the identity derived from it
    const auto adnl = c->addr;                    // where it is reachable
    assert(raw_key != short_id);                  // the confusion that rejected blocks
    assert(short_id != adnl);
    assert(raw_key != adnl);
    // For a classical descriptor the key identity is the same value as the membership
    // identity; for a post-quantum one they are independent, which is the point.
    assert(c->key_id.value == short_id);
    const auto* pq = set_after.get_validator(tos::ValidatorId{vid});
    assert(pq->validator_id.value != pq->key_id.value);
    assert(pq->validator_id.value != pq->addr);
    assert(pq->key_id.value != pq->addr);

    // Where a validator is reachable is answered from the descriptor, so a post-quantum
    // one uses the address it carries and a classical one with none falls back to the
    // identity derived from its key. Nothing derives it from a post-quantum key.
    assert(block::validator_adnl_identity(*pq) == pq->addr);
    assert(block::validator_adnl_identity(*c) == adnl);
    auto classical_no_addr = tos::ValidatorDescr{tos::Ed25519_PublicKey{fill(0x11)}, 5};
    assert(block::validator_adnl_identity(classical_no_addr) == short_id);
    assert(block::validator_adnl_identity(classical_no_addr) != raw_key);
  }

  {  // Serving a collate request needs both facts to agree. Two post-quantum validators
     // whose identities and addresses are all distinct, so a request can name one while
     // arriving on the other's address.
    const std::string key_c(tos::pq::mldsa44_public_key_bytes, '\x44');
    const auto kid_c = key_id_of(key_c);
    const auto vid_b = fill(0xa7), adnl_b = fill(0xc7);
    auto two =
        block::Config::unpack_validator_set(
            validator_set_cell(
                {pq_descriptor(vid, 1, kid_a, key_a, 5, adnl), pq_descriptor(vid_b, 1, kid_c, key_c, 7, adnl_b)}, 12),
            false)
            .move_as_ok();
    block::ValidatorSet vset{1, tos::ShardIdFull{tos::masterchainId}, two->export_validator_set()};

    // Each validator may ask for its own blocks, from its own address.
    assert(block::authorise_collate_request(vset, tos::ValidatorId{vid}, adnl).is_ok());
    assert(block::authorise_collate_request(vset, tos::ValidatorId{vid_b}, adnl_b).is_ok());
    // But not for someone else's: arriving as one validator and naming another is what
    // would otherwise let a member have blocks attributed to a peer.
    assert(block::authorise_collate_request(vset, tos::ValidatorId{vid_b}, adnl).is_error());
    assert(block::authorise_collate_request(vset, tos::ValidatorId{vid}, adnl_b).is_error());
    // Nor may a stranger, and nor does naming a member from an address that belongs to
    // no member help.
    assert(block::authorise_collate_request(vset, tos::ValidatorId{fill(0xee)}, adnl).is_error());
    assert(block::authorise_collate_request(vset, tos::ValidatorId{vid}, fill(0xee)).is_error());
  }

  {  // Constants that exist once per language. Each side checks its own against the
     // shared file, so a value changed on one side alone fails here instead of leaving
     // two implementations that disagree about the wire.
    std::map<std::string, unsigned long long> frozen;
    std::ifstream f(FROZEN_CONSTANTS_FILE);
    assert(f);
    std::string line;
    while (std::getline(f, line)) {
      if (line.empty() || line[0] == '#') {
        continue;
      }
      auto tab = line.find('\t');
      assert(tab != std::string::npos);
      frozen[line.substr(0, tab)] = std::stoull(line.substr(tab + 1));
    }
    auto frozen_value = [&](const char* name) {
      auto it = frozen.find(name);
      assert(it != frozen.end());
      return it->second;
    };
    assert(frozen.size() == 13);
    assert(tos::pq::pq_bytes_chunk == frozen_value("pq_bytes_chunk"));
    assert(tos::pq::pq_bytes_hard_max == frozen_value("pq_bytes_hard_max"));
    assert(tos::pq::mldsa44_public_key_bytes == frozen_value("mldsa44_public_key_bytes"));
    assert(tos::pq::mldsa44_signature_bytes == frozen_value("mldsa44_signature_bytes"));
    assert(static_cast<unsigned long long>(tos::pq::PQAlgorithmId::mldsa44) == frozen_value("mldsa44_algorithm_id"));
    assert(block::validator_set_hash_magic_v2 == frozen_value("validator_set_hash_magic_v2"));
    assert(tos::pq::elector_pq_stake_op == frozen_value("elector_pq_stake_op"));
    assert(tos::pq::elector_pq_stake_sign_tag == frozen_value("elector_pq_stake_sign_tag"));
    assert(tos::pq::config_pq_vote_op == frozen_value("config_pq_vote_op"));
    assert(tos::pq::config_pq_vote_sign_tag == frozen_value("config_pq_vote_sign_tag"));
    assert(tos::pq::elector_pq_complaint_op == frozen_value("elector_pq_complaint_op"));
    assert(tos::pq::elector_pq_complaint_sign_tag == frozen_value("elector_pq_complaint_sign_tag"));
    // The descriptor tag comes from the schema itself rather than a copy of it.
    const auto& tags = block::gen::ValidatorDescr::cons_tag;
    assert(std::find(std::begin(tags), std::end(tags), frozen_value("validator_descr_pq_tag")) != std::end(tags));
  }

  printf("VALIDATOR_IDENTITY_OK rotation keeps validator_id, changes key_id; bindings enforced; session binds both\n");
  return 0;
}
