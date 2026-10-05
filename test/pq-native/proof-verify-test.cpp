/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Production-path tests for the shared proof verifier (lite-client/proof-verify).
//
// Two sources of material:
//  * real lite-server answers captured from a local PQ network (zerostate anchor,
//    a chain through four key blocks, Config34, an account and get-methods, and a
//    live extension with a descent proof), committed under data/proof-verify-real;
//  * a synthetic signed chain built here (key-block anchor, rotation from
//    authority A to authority B), for controls that need signing keys.
//
// Every negative case names the refusal it must reach, so a case refused for
// another reason fails. `--case NAME` runs a single case.
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <functional>
#include <string>
#include <vector>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/mc-config.h"
#include "block/signature-set.h"
#include "block/validator-session-id.h"
#include "crypto/pq/consensus-pq-signer.h"
#include "crypto/pq/pq-bytes.h"
#include "lite-client/proof-verify/material.h"
#include "lite-client/proof-verify/proof-verify.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"
#include "test/pq-native/pq-block-signature-test-common.h"
#include "tl-utils/lite-utils.hpp"
#include "tos/lite-tl.hpp"
#include "tos/quorum.h"
#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"
#include "vm/dict.h"

namespace {

using namespace tos;
namespace pv = tos::proofverify;

std::string data_dir;
std::string only_case;
int failures = 0;
int passes = 0;

[[noreturn]] void die(const std::string& message) {
  std::fprintf(stderr, "PROOF_VERIFY_TEST_SETUP_FAILURE: %s\n", message.c_str());
  std::exit(2);
}

template <class T>
T must(td::Result<T> result, const std::string& where) {
  if (result.is_error()) {
    die(where + ": " + result.error().message().str());
  }
  return result.move_as_ok();
}

void must(td::Status status, const std::string& where) {
  if (status.is_error()) {
    die(where + ": " + status.message().str());
  }
}

bool selected(const std::string& name) {
  return only_case.empty() || only_case == name;
}

void record(const std::string& name, bool ok, const std::string& detail) {
  std::printf("PROOF_VERIFY_CASE %s %s %s\n", name.c_str(), ok ? "PASS" : "FAIL", detail.c_str());
  if (ok) {
    ++passes;
  } else {
    ++failures;
  }
}

void expect_verified(const std::string& name, const td::Result<pv::Verified>& result,
                     const std::function<std::string(const pv::Verified&)>& check = {}) {
  if (result.is_error()) {
    record(name, false, "refused: " + result.error().message().str());
    return;
  }
  std::string problem = check ? check(result.ok()) : std::string{};
  record(name, problem.empty(), problem.empty() ? "verified" : problem);
}

void expect_refused(const std::string& name, const td::Result<pv::Verified>& result, const std::string& reason) {
  if (result.is_ok()) {
    record(name, false, "accepted, expected refusal: " + reason);
    return;
  }
  const auto message = result.error().message().str();
  record(name, message.find(reason) != std::string::npos, "reason=" + message);
}

std::string read_text(const std::string& path) {
  return must(pv::read_bounded_file(path, 1u << 20), "read " + path);
}

// ---------------------------------------------------------------------------
// Real material.

struct RealFixture {
  pv::Anchor anchor;
  std::string historical_request_text;
  pv::Request historical_request;
  pv::Material historical;
  std::string live_request_text;
  pv::Request live_request;
  pv::Material live;
  pv::LiveState live_state;
  td::BufferSlice other_block_config;
};

RealFixture load_real() {
  RealFixture fixture;
  const auto root = data_dir + "/proof-verify-real";
  fixture.anchor = must(pv::parse_anchor(read_text(root + "/anchor.json")), "real anchor");
  fixture.historical_request_text = read_text(root + "/historical-request.json");
  fixture.historical_request = must(pv::parse_request(fixture.historical_request_text), "historical request");
  fixture.historical = must(pv::read_material(root + "/historical"), "historical material");
  fixture.live_request_text = read_text(root + "/live-request.json");
  fixture.live_request = must(pv::parse_request(fixture.live_request_text), "live request");
  fixture.live = must(pv::read_material(root + "/live"), "live material");
  fixture.live_state = must(pv::parse_state(read_text(root + "/live-state.json")), "live state");
  fixture.other_block_config =
      td::BufferSlice(must(pv::read_bounded_file(root + "/other-block-config.tl", 1u << 20), "other config"));
  return fixture;
}

pv::Material clone(const pv::Material& material) {
  pv::Material copy;
  auto opt = [](const std::optional<td::BufferSlice>& value) -> std::optional<td::BufferSlice> {
    if (!value) {
      return std::nullopt;
    }
    return value->clone();
  };
  copy.masterchain_info = opt(material.masterchain_info);
  copy.config = opt(material.config);
  copy.account = opt(material.account);
  copy.exec_config = opt(material.exec_config);
  copy.libraries = opt(material.libraries);
  for (const auto& item : material.chain) {
    copy.chain.push_back(item.clone());
  }
  for (const auto& item : material.descent) {
    copy.descent.push_back(item.clone());
  }
  return copy;
}

using ChainObject = tl_object_ptr<lite_api::liteServer_partialBlockProof>;

ChainObject parse_chain(const td::BufferSlice& raw) {
  return must(fetch_tl_object<lite_api::liteServer_partialBlockProof>(raw.clone(), true), "parse chain");
}

td::BufferSlice serialize_chain(const ChainObject& chain) {
  return serialize_tl_object(chain, true);
}

lite_api::liteServer_blockLinkForward& forward(ChainObject& chain, std::size_t index) {
  auto* link = dynamic_cast<lite_api::liteServer_blockLinkForward*>(chain->steps_.at(index).get());
  if (link == nullptr) {
    die("expected a forward link");
  }
  return *link;
}

lite_api::liteServer_signatureSet_simplexPq& pq_signatures(lite_api::liteServer_blockLinkForward& link) {
  auto* set = dynamic_cast<lite_api::liteServer_signatureSet_simplexPq*>(link.signatures_.get());
  if (set == nullptr) {
    die("expected a PQ signature set");
  }
  return *set;
}

tl_object_ptr<lite_api::liteServer_pqSignature> copy_signature(const lite_api::liteServer_pqSignature& signature) {
  return create_tl_object<lite_api::liteServer_pqSignature>(signature.validator_id_, signature.algorithm_id_,
                                                            signature.signature_.clone());
}

pv::Policy at(std::int64_t now) {
  pv::Policy policy;
  policy.now = now;
  return policy;
}

constexpr std::int64_t kHistoricalNow = 1791200932;
constexpr std::int64_t kLiveTargetUtime = 1791200930;

td::Result<pv::Verified> verify_historical(const RealFixture& fixture, const pv::Material& material,
                                           const pv::Anchor* anchor = nullptr, const pv::Request* request = nullptr) {
  return pv::verify(anchor ? *anchor : fixture.anchor, request ? *request : fixture.historical_request,
                    fixture.historical_request_text, material, std::nullopt, at(kHistoricalNow));
}

td::Result<pv::Verified> verify_live(const RealFixture& fixture, const pv::Material& material,
                                     const pv::LiveState& state, std::int64_t now) {
  return pv::verify(fixture.anchor, fixture.live_request, fixture.live_request_text, material, state, at(now));
}

pv::Material with_chain(const RealFixture& fixture, const std::function<void(ChainObject&)>& mutate) {
  auto material = clone(fixture.historical);
  auto chain = parse_chain(material.chain.at(0));
  mutate(chain);
  material.chain[0] = serialize_chain(chain);
  return material;
}

std::vector<std::string> print_rotation_evidence(const RealFixture& fixture) {
  std::vector<std::string> governing;
  auto chain = parse_chain(fixture.historical.chain.at(0));
  for (std::size_t i = 0; i < chain->steps_.size(); ++i) {
    auto& link = forward(chain, i);
    auto& set = pq_signatures(link);
    td::Bits256 signer_digest;
    std::vector<std::string> ids;
    for (const auto& signature : set.signatures_) {
      ids.push_back(signature->validator_id_.to_hex());
    }
    std::sort(ids.begin(), ids.end());
    std::string signers;
    for (const auto& id : ids) {
      signers += id;
    }
    td::sha256(signers, signer_digest.as_slice());
    // The governing set this link was checked against: ConfigParam 34 of the
    // source key block (or zerostate), read from the link's own source proof.
    auto proof_root = must(vm::std_boc_deserialize(link.config_proof_.as_slice()), "source proof");
    auto source_root = must(vm::MerkleProof::virtualize(proof_root), "source proof root");
    auto config = link.from_->seqno_ ? block::Config::extract_from_key_block(source_root, 0)
                                     : block::Config::extract_from_state(source_root, 0);
    auto source_config = must(std::move(config), "source configuration");
    auto validators = must(block::Config::unpack_validator_set(source_config->get_config_param(34)), "Config34");
    std::vector<std::string> members;
    for (const auto& descriptor : validators->list) {
      members.push_back(descriptor.validator_id.value.to_hex() + ":" + descriptor.key_id.value.to_hex());
    }
    std::sort(members.begin(), members.end());
    std::string member_text;
    for (const auto& member : members) {
      member_text += member;
    }
    td::Bits256 member_digest;
    td::sha256(member_text, member_digest.as_slice());
    std::printf("PROOF_VERIFY_REAL_GOVERNING_SET source=%u validators=%zu since=%u until=%u members_sha256=%s\n",
                static_cast<unsigned>(link.from_->seqno_), validators->list.size(), validators->utime_since,
                validators->utime_until, member_digest.to_hex().c_str());
    governing.push_back(member_digest.to_hex());
    std::printf(
        "PROOF_VERIFY_REAL_LINK index=%zu from=%u to=%u to_key=%d cc_seqno=%d vset_hash=%u signers=%zu "
        "signer_ids_sha256=%s\n",
        i, static_cast<unsigned>(link.from_->seqno_), static_cast<unsigned>(link.to_->seqno_),
        link.to_key_block_ ? 1 : 0, set.cc_seqno_, static_cast<unsigned>(set.validator_set_hash_),
        set.signatures_.size(), signer_digest.to_hex().c_str());
  }
  return governing;
}

// A link that cannot be converted or validated: any refusal other than the
// count check would come from trying to.
tl_object_ptr<lite_api::liteServer_BlockLink> unconvertible_link(const BlockIdExt& from, const BlockIdExt& to) {
  return create_tl_object<lite_api::liteServer_blockLinkForward>(
      false, create_tl_lite_block_id(from), create_tl_lite_block_id(to), td::BufferSlice(), td::BufferSlice(),
      create_tl_object<lite_api::liteServer_signatureSet_simplexPq>(
          0, 0, std::vector<tl_object_ptr<lite_api::liteServer_pqSignature>>{}, td::Bits256::zero(), 0,
          td::BufferSlice()));
}

td::BufferSlice oversized_chain(const BlockIdExt& from, const BlockIdExt& to, bool complete, std::size_t links) {
  std::vector<tl_object_ptr<lite_api::liteServer_BlockLink>> steps;
  steps.reserve(links);
  for (std::size_t i = 0; i < links; ++i) {
    steps.push_back(unconvertible_link(from, to));
  }
  return create_serialize_tl_object<lite_api::liteServer_partialBlockProof>(
      complete, create_tl_lite_block_id(from), create_tl_lite_block_id(to), std::move(steps));
}

void real_cases(const RealFixture& fixture, const pv::Anchor& foreign_anchor, const td::BufferSlice& foreign_chain) {
  if (selected("real-historical-baseline")) {
    // The real chain must cross a membership/key rotation for this baseline to
    // show that a legitimate rotation is followed.
    const auto governing = print_rotation_evidence(fixture);
    expect_verified("real-historical-baseline", verify_historical(fixture, fixture.historical),
                    [&](const pv::Verified& verified) -> std::string {
                      if (governing.size() != 5 || governing.front() == governing.back()) {
                        return "real chain does not cross a validator-set rotation";
                      }
                      if (verified.links != 5 || verified.key_blocks.size() != 4 || verified.target.seqno() != 636922 ||
                          verified.params.size() != 1 || verified.params[0].index != 34 || !verified.account ||
                          verified.get_methods.size() != 2 ||
                          verified.get_methods[0].stack_json.find("1791201224") == std::string::npos) {
                        return "unexpected verified content";
                      }
                      std::printf("PROOF_VERIFY_REAL_RESULT %s\n",
                                  pv::render_verified(verified).substr(0, 600).c_str());
                      return {};
                    });
  }
  // Control 1: a different anchor with this network's chain, and this anchor
  // with another network's otherwise valid chain.
  if (selected("real-anchor-substituted")) {
    expect_refused("real-anchor-substituted", verify_historical(fixture, fixture.historical, &foreign_anchor),
                   "does not start at the authenticated block");
  }
  if (selected("real-foreign-chain")) {
    auto material = clone(fixture.historical);
    material.chain[0] = foreign_chain.clone();
    expect_refused("real-foreign-chain", verify_historical(fixture, material),
                   "does not start at the authenticated block");
  }
  // Control 2.
  if (selected("real-forged-signature")) {
    expect_refused("real-forged-signature",
                   verify_historical(fixture, with_chain(fixture,
                                                         [](ChainObject& chain) {
                                                           auto& signature =
                                                               pq_signatures(forward(chain, 2)).signatures_.at(0);
                                                           signature->signature_.as_slice()[100] ^= 1;
                                                         })),
                   "invalid signature");
  }
  if (selected("real-unknown-signer")) {
    expect_refused("real-unknown-signer",
                   verify_historical(fixture, with_chain(fixture,
                                                         [](ChainObject& chain) {
                                                           // A quorum of genuine signers plus one outsider.
                                                           auto& set = pq_signatures(forward(chain, 2));
                                                           auto outsider = copy_signature(*set.signatures_.at(0));
                                                           outsider->validator_id_.as_slice()[0] ^= 1;
                                                           set.signatures_.push_back(std::move(outsider));
                                                         })),
                   "unknown validator_id");
  }
  if (selected("real-duplicate-signer")) {
    expect_refused("real-duplicate-signer",
                   verify_historical(fixture, with_chain(fixture,
                                                         [](ChainObject& chain) {
                                                           auto& set = pq_signatures(forward(chain, 2));
                                                           auto first = copy_signature(*set.signatures_.at(0));
                                                           set.signatures_.resize(2);
                                                           set.signatures_.push_back(std::move(first));
                                                         })),
                   "duplicate validator_id");
  }
  if (selected("real-insufficient-quorum")) {
    expect_refused(
        "real-insufficient-quorum",
        verify_historical(
            fixture,
            with_chain(fixture, [](ChainObject& chain) { pq_signatures(forward(chain, 2)).signatures_.resize(2); })),
        "insufficient verified weight");
  }
  // Control 4: classic carrier substituted for the PQ carrier.
  if (selected("real-classic-carrier")) {
    expect_refused(
        "real-classic-carrier",
        verify_historical(fixture, with_chain(fixture,
                                              [](ChainObject& chain) {
                                                auto& link = forward(chain, 2);
                                                auto& set = pq_signatures(link);
                                                link.signatures_ =
                                                    create_tl_object<lite_api::liteServer_signatureSet_ordinary>(
                                                        set.validator_set_hash_, set.cc_seqno_,
                                                        std::vector<tl_object_ptr<lite_api::liteServer_signature>>{});
                                              })),
        "does not carry a post-quantum finality signature set");
  }
  // Control 5.
  if (selected("real-missing-link")) {
    expect_refused(
        "real-missing-link",
        verify_historical(
            fixture, with_chain(fixture, [](ChainObject& chain) { chain->steps_.erase(chain->steps_.begin() + 2); })),
        "begins with block");
  }
  if (selected("real-reordered-links")) {
    expect_refused(
        "real-reordered-links",
        verify_historical(
            fixture, with_chain(fixture, [](ChainObject& chain) { std::swap(chain->steps_[1], chain->steps_[2]); })),
        "begins with block");
  }
  if (selected("real-truncated-chain")) {
    expect_refused("real-truncated-chain",
                   verify_historical(fixture, with_chain(fixture,
                                                         [](ChainObject& chain) {
                                                           chain->steps_.pop_back();
                                                           auto& last = forward(chain, chain->steps_.size() - 1);
                                                           chain->to_ =
                                                               create_tl_lite_block_id(create_block_id(last.to_));
                                                         })),
                   "does not end at the exact target block");
  }
  if (selected("real-wrong-target")) {
    auto request = fixture.historical_request;
    request.target->root_hash.as_slice()[0] ^= 1;
    expect_refused("real-wrong-target", verify_historical(fixture, fixture.historical, nullptr, &request),
                   "does not end at the exact target block");
  }
  // Control 7: block/state-root mismatch and a substituted configuration proof.
  if (selected("real-config-other-block-header")) {
    auto material = clone(fixture.historical);
    auto config = must(fetch_tl_object<lite_api::liteServer_configInfo>(material.config->clone(), true), "config");
    auto chain = parse_chain(fixture.historical.chain.at(0));
    // A genuine header proof, of another block, offered for the target.
    config->state_proof_ = forward(chain, 0).dest_proof_.clone();
    material.config = serialize_tl_object(config, true);
    expect_refused("real-config-other-block-header", verify_historical(fixture, material), "has incorrect root hash");
  }
  if (selected("real-config-substituted-state")) {
    auto material = clone(fixture.historical);
    auto config = must(fetch_tl_object<lite_api::liteServer_configInfo>(material.config->clone(), true), "config");
    auto other =
        must(fetch_tl_object<lite_api::liteServer_configInfo>(fixture.other_block_config.clone(), true), "other");
    config->config_proof_ = other->config_proof_.clone();
    material.config = serialize_tl_object(config, true);
    expect_refused("real-config-substituted-state", verify_historical(fixture, material),
                   "root hash mismatch in the shardchain state proof");
  }
  if (selected("real-config-other-block-answer")) {
    auto material = clone(fixture.historical);
    material.config = fixture.other_block_config.clone();
    expect_refused("real-config-other-block-answer", verify_historical(fixture, material),
                   "configuration proof answers for another block");
  }
  // Control 11: omitted or malformed material never produces a result.
  if (selected("real-omitted-config")) {
    auto material = clone(fixture.historical);
    material.config.reset();
    expect_refused("real-omitted-config", verify_historical(fixture, material), "configuration proof is missing");
  }
  if (selected("real-omitted-execution-config")) {
    auto material = clone(fixture.historical);
    material.exec_config.reset();
    expect_refused("real-omitted-execution-config", verify_historical(fixture, material),
                   "execution configuration proof is missing");
  }
  if (selected("real-omitted-chain")) {
    auto material = clone(fixture.historical);
    material.chain.clear();
    expect_refused("real-omitted-chain", verify_historical(fixture, material), "no proof chain reaches the target");
  }
  if (selected("real-malformed-chain")) {
    auto material = clone(fixture.historical);
    material.chain[0].truncate(material.chain[0].size() / 2);
    expect_refused("real-malformed-chain", verify_historical(fixture, material), "not the expected lite API answer");
  }
  // Control 10.
  if (selected("real-live-baseline")) {
    expect_verified("real-live-baseline", verify_live(fixture, fixture.live, fixture.live_state, kLiveTargetUtime + 2),
                    [](const pv::Verified& verified) -> std::string {
                      if (!verified.descends_from || verified.descends_from->seqno() != 636888 ||
                          verified.start.seqno() != 5243 || !verified.next_state || !verified.next_state->head ||
                          verified.next_state->head->id.seqno() != 636922) {
                        return "live result lacks descent or next state";
                      }
                      return {};
                    });
  }
  if (selected("real-live-expired")) {
    expect_refused("real-live-expired", verify_live(fixture, fixture.live, fixture.live_state, kLiveTargetUtime + 301),
                   "above the maximum age");
  }
  if (selected("real-live-future")) {
    expect_refused("real-live-future", verify_live(fixture, fixture.live, fixture.live_state, kLiveTargetUtime - 61),
                   "dated in the future");
  }
  if (selected("real-live-rollback")) {
    auto state = fixture.live_state;
    state.head->id.id.seqno = 636923;
    expect_refused("real-live-rollback", verify_live(fixture, fixture.live, state, kLiveTargetUtime + 2),
                   "rollback refused");
  }
  if (selected("real-live-same-height-conflict")) {
    auto state = fixture.live_state;
    state.head->id.id.seqno = 636922;
    expect_refused("real-live-same-height-conflict", verify_live(fixture, fixture.live, state, kLiveTargetUtime + 2),
                   "conflicts with the verified head");
  }
  if (selected("real-live-missing-descent")) {
    auto material = clone(fixture.live);
    material.descent.clear();
    expect_refused("real-live-missing-descent",
                   verify_live(fixture, material, fixture.live_state, kLiveTargetUtime + 2),
                   "needs exactly one backward proof");
  }
  if (selected("real-live-oversized-descent")) {
    auto material = clone(fixture.live);
    const auto target = fixture.live_request.target ? *fixture.live_request.target : fixture.live_state.head->id;
    material.descent[0] = oversized_chain(target, fixture.live_state.head->id, true, pv::kMaxDescentLinks + 1);
    expect_refused("real-live-oversized-descent",
                   verify_live(fixture, material, fixture.live_state, kLiveTargetUtime + 2),
                   "descent proof has too many links");
  }
  if (selected("real-live-other-head")) {
    auto state = fixture.live_state;
    state.head->id.root_hash.as_slice()[0] ^= 1;
    expect_refused("real-live-other-head", verify_live(fixture, fixture.live, state, kLiveTargetUtime + 2),
                   "does not connect the target to the verified head");
  }
  if (selected("real-historical-old-still-valid")) {
    expect_verified("real-historical-old-still-valid",
                    pv::verify(fixture.anchor, fixture.historical_request, fixture.historical_request_text,
                               fixture.historical, std::nullopt, at(kHistoricalNow + 10LL * 365 * 86400)));
  }
}

// ---------------------------------------------------------------------------
// Synthetic signed chain.

using pq_block_signature_test::candidate;
using pq_block_signature_test::hash_of;

td::Bits256 key_bits(const pq::ConsensusPQKey& key) {
  td::Bits256 result;
  std::memcpy(result.data(), key.key_id.data(), key.key_id.size());
  return result;
}

td::Ref<vm::Cell> empty_dictionary() {
  vm::CellBuilder builder;
  builder.store_bool_bool(false);
  return builder.finalize_novm();
}

td::Ref<vm::Cell> pq_descriptor(const ValidatorDescr& descr) {
  vm::CellBuilder builder;
  if (!(builder.store_long_bool(0xb3, 8) && builder.store_bits_bool(descr.validator_id.value.cbits(), 256) &&
        builder.store_long_bool(descr.algorithm_id, 16) && builder.store_bits_bool(descr.key_id.value.cbits(), 256) &&
        builder.store_ref_bool(
            must(pq::pack_pq_bytes(td::Slice(descr.pq_public_key), pq::pq_bytes_hard_max), "pack public key")) &&
        builder.store_long_bool(static_cast<long long>(descr.weight), 64) &&
        builder.store_bits_bool(descr.addr.cbits(), 256))) {
    die("descriptor build");
  }
  return builder.finalize_novm();
}

td::Ref<vm::Cell> validator_set_cell(const std::vector<ValidatorDescr>& validators) {
  vm::Dictionary dictionary{16};
  ValidatorWeight total_weight = 0;
  for (std::size_t i = 0; i < validators.size(); ++i) {
    if (!dictionary.set(td::BitArray<16>{static_cast<unsigned>(i)}.cbits(), 16,
                        vm::load_cell_slice_ref(pq_descriptor(validators[i])))) {
      die("validator dictionary build");
    }
    if (!checked_add_validator_weight(total_weight, validators[i].weight)) {
      die("validator weight overflow");
    }
  }
  vm::CellBuilder builder;
  if (!(builder.store_long_bool(0x12, 8) && builder.store_long_bool(1, 32) && builder.store_long_bool(0x7fffffff, 32) &&
        builder.store_long_bool(validators.size(), 16) && builder.store_long_bool(validators.size(), 16) &&
        builder.store_long_bool(static_cast<long long>(total_weight), 64) &&
        builder.store_maybe_ref(std::move(dictionary).extract_root_cell()))) {
    die("validator set build");
  }
  return builder.finalize_novm();
}

td::Ref<vm::Cell> consensus_options_cell() {
  block::gen::ConsensusConfig::Record_consensus_config_v3 record{
      .flags = 0,
      .new_catchain_ids = true,
      .round_candidates = 7,
      .next_candidate_delay_ms = 20,
      .consensus_timeout_ms = 100,
      .fast_attempts = 3,
      .attempt_duration = 8,
      .catchain_max_deps = 4,
      .max_block_bytes = 2U * 1024U * 1024U,
      .max_collated_bytes = 3U * 1024U * 1024U,
      .proto_version = 1,
  };
  td::Ref<vm::Cell> result;
  if (!block::gen::t_ConsensusConfig.cell_pack(result, record)) {
    die("Param29 build");
  }
  return result;
}

td::Ref<vm::Cell> simplex_config_cell(unsigned discriminator) {
  block::gen::NewConsensusConfig::Record_simplex_config record{
      .flags = 0,
      .use_quic = false,
      .target_rate_ms = 400 + discriminator,
      .slots_per_leader_window = 4,
      .first_block_timeout_ms = 1000,
      .max_leader_window_desync = 250,
  };
  td::Ref<vm::Cell> result;
  if (!block::gen::t_NewConsensusConfig.cell_pack(result, record)) {
    die("Param30 build");
  }
  return result;
}

td::Ref<vm::Cell> config_dictionary(const std::vector<ValidatorDescr>& validators, unsigned discriminator,
                                    td::int32 global_id) {
  vm::CellBuilder all;
  if (!(all.store_long_bool(0x10, 8) && all.store_bool_bool(true) &&
        all.store_ref_bool(simplex_config_cell(discriminator)) && all.store_bool_bool(true) &&
        all.store_ref_bool(simplex_config_cell(discriminator + 100)))) {
    die("Param30 wrapper build");
  }
  vm::Dictionary dictionary{32};
  if (!(dictionary.set_ref(td::BitArray<32>{19}, vm::CellBuilder{}.store_long(global_id, 32).finalize_novm()) &&
        dictionary.set_ref(td::BitArray<32>{29}, consensus_options_cell()) &&
        dictionary.set_ref(td::BitArray<32>{30}, all.finalize_novm()) &&
        dictionary.set_ref(td::BitArray<32>{34}, validator_set_cell(validators)))) {
    die("config dictionary build");
  }
  return std::move(dictionary).extract_root_cell();
}

td::Ref<vm::Cell> config_params(const td::Ref<vm::Cell>& dictionary) {
  vm::CellBuilder builder;
  builder.store_zeroes(256);
  if (!builder.store_ref_bool(dictionary)) {
    die("ConfigParams build");
  }
  return builder.finalize_novm();
}

td::Ref<vm::Cell> ext_block_ref(const BlockIdExt& id) {
  vm::CellBuilder builder;
  if (!(builder.store_long_bool(id.seqno() * 1000ULL, 64) && builder.store_long_bool(id.seqno(), 32) &&
        builder.store_bits_bool(id.root_hash.cbits(), 256) && builder.store_bits_bool(id.file_hash.cbits(), 256))) {
    die("ExtBlkRef build");
  }
  return builder.finalize_novm();
}

struct BlockFixture {
  BlockIdExt id;
  td::Ref<vm::Cell> root;
  block::gen::BlockInfo::Record info;
};

// Generation time of synthetic blocks: fixed for the unit cases, the current
// time for the live fixture written for the CLI commit test.
td::uint32 block_time_base = 1000;

BlockFixture make_block(td::int32 global_id, BlockSeqno seqno, const BlockIdExt& previous, td::uint32 catchain_seqno,
                        td::uint32 validator_set_hash, BlockSeqno previous_key_block_seqno,
                        td::Ref<vm::Cell> next_config, td::uint32 utime_extra = 0) {
  block::gen::BlockInfo::Record info;
  info.version = 0;
  info.not_master = false;
  info.after_merge = info.before_split = info.after_split = false;
  info.want_split = info.want_merge = false;
  info.key_block = next_config.not_null();
  info.vert_seqno_incr = false;
  info.flags = 0;
  info.seq_no = seqno;
  info.vert_seq_no = 0;
  vm::CellBuilder shard;
  block::ShardId{ShardIdFull{masterchainId}}.serialize(shard);
  info.shard = shard.as_cellslice_ref();
  info.gen_utime = block_time_base + seqno + utime_extra;
  info.start_lt = seqno * 1000ULL;
  info.end_lt = info.start_lt + 1;
  info.gen_validator_list_hash_short = validator_set_hash;
  info.gen_catchain_seqno = catchain_seqno;
  info.min_ref_mc_seqno = previous.seqno();
  info.prev_key_block_seqno = previous_key_block_seqno;
  info.prev_ref = ext_block_ref(previous);
  td::Ref<vm::Cell> info_cell;
  if (!block::gen::t_BlockInfo.cell_pack(info_cell, info)) {
    die("BlockInfo build");
  }
  auto empty = empty_dictionary();
  vm::CellBuilder empty_fees_builder;
  empty_fees_builder.store_zeroes(11);
  block::gen::McBlockExtra::Record mc_extra;
  mc_extra.key_block = next_config.not_null();
  mc_extra.shard_hashes = vm::load_cell_slice_ref(empty);
  mc_extra.shard_fees = vm::load_cell_slice_ref(empty_fees_builder.finalize_novm());
  mc_extra.r1.prev_blk_signatures = vm::load_cell_slice_ref(empty);
  mc_extra.r1.recover_create_msg = vm::load_cell_slice_ref(empty);
  mc_extra.r1.mint_msg = vm::load_cell_slice_ref(empty);
  if (next_config.not_null()) {
    mc_extra.config = vm::load_cell_slice_ref(config_params(next_config));
  }
  td::Ref<vm::Cell> mc_extra_cell;
  if (!block::gen::t_McBlockExtra.cell_pack(mc_extra_cell, mc_extra)) {
    die("McBlockExtra build");
  }
  block::gen::BlockExtra::Record extra;
  extra.in_msg_descr = empty;
  extra.out_msg_descr = empty;
  extra.account_blocks = empty;
  vm::CellBuilder custom;
  if (!(custom.store_bool_bool(true) && custom.store_ref_bool(mc_extra_cell))) {
    die("BlockExtra custom build");
  }
  extra.custom = custom.as_cellslice_ref();
  td::Ref<vm::Cell> extra_cell;
  if (!block::gen::t_BlockExtra.cell_pack(extra_cell, extra)) {
    die("BlockExtra build");
  }
  auto root = vm::CellBuilder{}
                  .store_long(0x11ef55aa, 32)
                  .store_long(global_id, 32)
                  .store_ref(info_cell)
                  .store_ref(empty)
                  .store_ref(empty)
                  .store_ref(extra_cell)
                  .finalize_novm();
  auto data = must(vm::std_boc_serialize(root, 31), "block boc");
  td::Bits256 file_hash;
  td::sha256(data.as_slice(), file_hash.as_slice());
  return {BlockIdExt{masterchainId, shardIdAll, seqno, td::Bits256{root->get_hash().bits()}, file_hash},
          std::move(root), std::move(info)};
}

td::BufferSlice proof_boc(const td::Ref<vm::Cell>& root) {
  auto proof = must(vm::MerkleProof::generate(root, [](const td::Ref<vm::Cell>&) { return false; }), "proof");
  return must(vm::std_boc_serialize(proof, 31), "proof boc");
}

struct Authority {
  std::vector<pq::ValidatorPQKeyStore> stores;
  std::vector<ValidatorDescr> descriptors;

  Authority(std::size_t count, unsigned discriminator) {
    for (std::size_t i = 0; i < count; ++i) {
      std::array<char, 32> seed{};
      for (std::size_t j = 0; j < seed.size(); ++j) {
        seed[j] = static_cast<char>((i * 31 + j * 13 + discriminator * 59) & 0xff);
      }
      auto store = pq::ValidatorPQKeyStore::from_seed(std::string_view(seed.data(), seed.size()));
      if (!store.has_value()) {
        die("key derivation");
      }
      const auto& key = store->consensus_key();
      descriptors.emplace_back(
          ValidatorId{hash_of("proof-verify-validator-" + std::to_string(discriminator) + "-" + std::to_string(i))},
          static_cast<td::uint16>(key.algorithm_id), ConsensusKeyId{key_bits(key)}, key.public_key, 1,
          hash_of("proof-verify-adnl-" + std::to_string(discriminator) + "-" + std::to_string(i)));
      stores.push_back(std::move(*store));
    }
  }
};

ValidatorSessionId session_for(td::int32 global_id, const td::Ref<vm::Cell>& config_root,
                               const td::Ref<block::ValidatorSet>& validator_set, const BlockFixture& destination) {
  block::Config config{config_root};
  must(config.unpack(), "config unpack");
  auto selected_config = config.get_selected_new_consensus_config(masterchainId);
  if (!selected_config) {
    die("selected Param30 missing");
  }
  auto options = config.get_consensus_config();
  return block::derive_validator_session_identity(
             global_id, block::validator_session_options_hash(options), selected_config.value().cell_hash,
             ShardIdFull{masterchainId}, validator_set->get_catchain_seqno(), validator_set->export_vector(),
             destination.info.vert_seq_no, destination.info.prev_key_block_seqno, options.new_catchain_ids)
      .session_id;
}

struct SignOptions {
  bool final_vote{true};
  std::optional<BlockIdExt> candidate_block;
  std::size_t signers{~std::size_t{0}};
};

td::Ref<block::BlockSignatureSet> sign(const Authority& authority, const td::Ref<block::ValidatorSet>& carried_set,
                                       const BlockFixture& destination, ValidatorSessionId session, td::uint32 slot,
                                       SignOptions options = {}) {
  const auto candidate_id = options.candidate_block.value_or(destination.id);
  auto preimage = must(block::BlockSignatureSet::build_simplex_data_to_sign(session, slot, candidate(candidate_id),
                                                                            options.final_vote, candidate_id),
                       "vote preimage");
  std::vector<block::PQBlockSignature> pairs;
  for (std::size_t i = 0; i < authority.stores.size() && i < options.signers; ++i) {
    auto signature = authority.stores[i].sign_consensus(std::string_view(preimage.data(), preimage.size()));
    if (!signature.has_value()) {
      die("vote signature");
    }
    pairs.push_back(
        {authority.descriptors[i].validator_id, signature->algorithm_id, td::BufferSlice(signature->signature)});
  }
  return must(block::BlockSignatureSet::create_simplex_pq_final(std::move(pairs), carried_set->get_catchain_seqno(),
                                                                carried_set->get_validator_set_hash(), session, slot,
                                                                candidate(candidate_id)),
              "signature set");
}

struct LinkSpec {
  const BlockFixture* from;
  const BlockFixture* to;
  tl_object_ptr<lite_api::liteServer_SignatureSet> signatures;
};

td::BufferSlice chain_wire(const BlockIdExt& from, const BlockIdExt& to, bool complete, std::vector<LinkSpec> links) {
  std::vector<tl_object_ptr<lite_api::liteServer_BlockLink>> steps;
  for (auto& link : links) {
    steps.push_back(create_tl_object<lite_api::liteServer_blockLinkForward>(
        link.to->info.key_block, create_tl_lite_block_id(link.from->id), create_tl_lite_block_id(link.to->id),
        proof_boc(link.to->root), proof_boc(link.from->root), std::move(link.signatures)));
  }
  return create_serialize_tl_object<lite_api::liteServer_partialBlockProof>(
      complete, create_tl_lite_block_id(from), create_tl_lite_block_id(to), std::move(steps));
}

struct Synthetic {
  td::int32 global_id{-217};
  Authority a{4, 1};
  Authority b{4, 2};
  Authority x{4, 3};
  td::Ref<vm::Cell> config_a, config_b, config_x;
  td::Ref<block::ValidatorSet> set_a, set_b, set_x;
  BlockFixture k0, k1, t, k1x, tx, k1y, ty;
  ValidatorSessionId session_k1, session_t;
  pv::Anchor anchor;
  pv::Request request;
  std::string request_text;

  Synthetic() {
    config_a = config_dictionary(a.descriptors, 1, global_id);
    config_b = config_dictionary(b.descriptors, 2, global_id);
    config_x = config_dictionary(x.descriptors, 3, global_id);
    set_a = td::Ref<block::ValidatorSet>{true, 101, ShardIdFull{masterchainId}, a.descriptors};
    set_b = td::Ref<block::ValidatorSet>{true, 102, ShardIdFull{masterchainId}, b.descriptors};
    set_x = td::Ref<block::ValidatorSet>{true, 102, ShardIdFull{masterchainId}, x.descriptors};
    BlockIdExt zero{masterchainId, shardIdAll, 0, hash_of("proof-verify-zero-root"), hash_of("proof-verify-zero-file")};
    k0 = make_block(global_id, 1, zero, 100, 0, 0, config_a);
    k1 = make_block(global_id, 2, k0.id, set_a->get_catchain_seqno(), set_a->get_validator_set_hash(), 1, config_b);
    t = make_block(global_id, 3, k1.id, set_b->get_catchain_seqno(), set_b->get_validator_set_hash(), 2, {});
    // An attacker key block naming its own set, claiming the set it replaces.
    // Attacker key blocks carrying the attacker's own configuration: k1x names
    // the attacker's set in its header, k1y claims the set it replaces.
    k1x = make_block(global_id, 2, k0.id, set_x->get_catchain_seqno(), set_x->get_validator_set_hash(), 1, config_x);
    tx = make_block(global_id, 3, k1x.id, set_x->get_catchain_seqno(), set_x->get_validator_set_hash(), 2, {});
    k1y = make_block(global_id, 2, k0.id, set_a->get_catchain_seqno(), set_a->get_validator_set_hash(), 1, config_x);
    ty = make_block(global_id, 3, k1y.id, set_x->get_catchain_seqno(), set_x->get_validator_set_hash(), 2, {});
    session_k1 = session_for(global_id, config_a, set_a, k1);
    session_t = session_for(global_id, config_b, set_b, t);
    anchor.kind = pv::AnchorKind::KeyBlock;
    anchor.id = k0.id;
    request_text = "{\"mode\":\"historical\",\"target\":" + pv::block_id_json(t.id) + "}";
    request = must(pv::parse_request(request_text), "synthetic request");
  }

  tl_object_ptr<lite_api::liteServer_SignatureSet> good_k1() const {
    return sign(a, set_a, k1, session_k1, 2001)->tl_lite();
  }
  tl_object_ptr<lite_api::liteServer_SignatureSet> good_t() const {
    return sign(b, set_b, t, session_t, 2002)->tl_lite();
  }
  td::BufferSlice chain(tl_object_ptr<lite_api::liteServer_SignatureSet> first,
                        tl_object_ptr<lite_api::liteServer_SignatureSet> second) const {
    std::vector<LinkSpec> links;
    links.push_back({&k0, &k1, std::move(first)});
    links.push_back({&k1, &t, std::move(second)});
    return chain_wire(k0.id, t.id, true, std::move(links));
  }
  td::Result<pv::Verified> run(std::vector<td::BufferSlice> responses, const pv::Anchor* other = nullptr) const {
    pv::Material material;
    material.chain = std::move(responses);
    return pv::verify(other ? *other : anchor, request, request_text, material, std::nullopt, at(kHistoricalNow));
  }
};

std::vector<td::BufferSlice> one(td::BufferSlice response) {
  std::vector<td::BufferSlice> result;
  result.push_back(std::move(response));
  return result;
}

void synthetic_cases(const Synthetic& s, const pv::Anchor& real_anchor) {
  if (selected("synthetic-rotation-baseline")) {
    expect_verified("synthetic-rotation-baseline", s.run(one(s.chain(s.good_k1(), s.good_t()))),
                    [&](const pv::Verified& verified) -> std::string {
                      if (verified.links != 2 || verified.key_blocks.size() != 1 || verified.key_blocks[0] != s.k1.id) {
                        return "rotation key block not reported";
                      }
                      return {};
                    });
  }
  if (selected("synthetic-split-responses")) {
    std::vector<td::BufferSlice> responses;
    std::vector<LinkSpec> first;
    first.push_back({&s.k0, &s.k1, s.good_k1()});
    // An incomplete answer names the block it reached, as the lite-server does.
    responses.push_back(chain_wire(s.k0.id, s.k1.id, false, std::move(first)));
    std::vector<LinkSpec> second;
    second.push_back({&s.k1, &s.t, s.good_t()});
    responses.push_back(chain_wire(s.k1.id, s.t.id, true, std::move(second)));
    expect_verified("synthetic-split-responses", s.run(std::move(responses)));
  }
  if (selected("synthetic-gap-between-responses")) {
    std::vector<td::BufferSlice> responses;
    std::vector<LinkSpec> first;
    first.push_back({&s.k0, &s.k1, s.good_k1()});
    responses.push_back(chain_wire(s.k0.id, s.k1.id, false, std::move(first)));
    responses.push_back(s.chain(s.good_k1(), s.good_t()));
    expect_refused("synthetic-gap-between-responses", s.run(std::move(responses)),
                   "does not start at the authenticated block");
  }
  // Link-count bounds hold before any link is converted or validated.
  if (selected("synthetic-oversized-single-response")) {
    expect_refused("synthetic-oversized-single-response",
                   s.run(one(oversized_chain(s.k0.id, s.t.id, true, pv::kMaxChainLinks + 1))),
                   "proof chain has too many links");
  }
  if (selected("synthetic-cumulative-link-overflow")) {
    std::vector<td::BufferSlice> responses;
    std::vector<LinkSpec> first;
    first.push_back({&s.k0, &s.k1, s.good_k1()});
    responses.push_back(chain_wire(s.k0.id, s.k1.id, false, std::move(first)));
    responses.push_back(oversized_chain(s.k1.id, s.t.id, true, pv::kMaxChainLinks));
    expect_refused("synthetic-cumulative-link-overflow", s.run(std::move(responses)), "proof chain has too many links");
  }
  if (selected("synthetic-real-anchor")) {
    expect_refused("synthetic-real-anchor", s.run(one(s.chain(s.good_k1(), s.good_t())), &real_anchor),
                   "does not start at the authenticated block");
  }
  // Control 2 on the synthetic chain.
  if (selected("synthetic-insufficient-quorum")) {
    SignOptions options;
    options.signers = 2;
    expect_refused("synthetic-insufficient-quorum",
                   s.run(one(s.chain(sign(s.a, s.set_a, s.k1, s.session_k1, 2001, options)->tl_lite(), s.good_t()))),
                   "insufficient verified weight");
  }
  // Control 3: valid signatures of the outgoing set on a block the incoming set governs.
  if (selected("synthetic-wrong-validator-set")) {
    expect_refused("synthetic-wrong-validator-set",
                   s.run(one(s.chain(s.good_k1(), sign(s.a, s.set_b, s.t, s.session_t, 2002)->tl_lite()))),
                   "unknown validator_id");
  }
  if (selected("synthetic-wrong-validator-set-hash")) {
    expect_refused("synthetic-wrong-validator-set-hash",
                   s.run(one(s.chain(s.good_k1(), sign(s.a, s.set_a, s.t, s.session_t, 2002)->tl_lite()))),
                   "catchain seqno mismatch");
  }
  // Control 4.
  if (selected("synthetic-wrong-session")) {
    auto session = s.session_k1;
    session.as_slice()[0] ^= 1;
    expect_refused("synthetic-wrong-session",
                   s.run(one(s.chain(sign(s.a, s.set_a, s.k1, session, 2001)->tl_lite(), s.good_t()))),
                   "carried session_id does not match");
  }
  if (selected("synthetic-wrong-network-session")) {
    auto session = session_for(s.global_id + 1, s.config_a, s.set_a, s.k1);
    expect_refused("synthetic-wrong-network-session",
                   s.run(one(s.chain(sign(s.a, s.set_a, s.k1, session, 2001)->tl_lite(), s.good_t()))),
                   "carried session_id does not match");
  }
  if (selected("synthetic-wrong-config-session")) {
    auto session = session_for(s.global_id, config_dictionary(s.a.descriptors, 7, s.global_id), s.set_a, s.k1);
    expect_refused("synthetic-wrong-config-session",
                   s.run(one(s.chain(sign(s.a, s.set_a, s.k1, session, 2001)->tl_lite(), s.good_t()))),
                   "carried session_id does not match");
  }
  if (selected("synthetic-wrong-candidate")) {
    SignOptions options;
    options.candidate_block = s.t.id;
    expect_refused("synthetic-wrong-candidate",
                   s.run(one(s.chain(sign(s.a, s.set_a, s.k1, s.session_k1, 2001, options)->tl_lite(), s.good_t()))),
                   "block id mismatch");
  }
  if (selected("synthetic-approve-role")) {
    SignOptions options;
    options.final_vote = false;
    expect_refused("synthetic-approve-role",
                   s.run(one(s.chain(sign(s.a, s.set_a, s.k1, s.session_k1, 2001, options)->tl_lite(), s.good_t()))),
                   "invalid signature");
  }
  if (selected("synthetic-wrong-slot")) {
    auto set = sign(s.a, s.set_a, s.k1, s.session_k1, 2001);
    auto lite = set->tl_lite();
    dynamic_cast<lite_api::liteServer_signatureSet_simplexPq&>(*lite).slot_ = 2009;
    expect_refused("synthetic-wrong-slot", s.run(one(s.chain(std::move(lite), s.good_t()))), "invalid signature");
  }
  // Control 5.
  if (selected("synthetic-missing-link")) {
    std::vector<LinkSpec> links;
    links.push_back({&s.k1, &s.t, s.good_t()});
    expect_refused("synthetic-missing-link", s.run(one(chain_wire(s.k0.id, s.t.id, true, std::move(links)))),
                   "begins with block");
  }
  if (selected("synthetic-wrong-origin")) {
    std::vector<LinkSpec> links;
    links.push_back({&s.k1, &s.t, s.good_t()});
    expect_refused("synthetic-wrong-origin", s.run(one(chain_wire(s.k1.id, s.t.id, true, std::move(links)))),
                   "does not start at the authenticated block");
  }
  if (selected("synthetic-incomplete-last-response")) {
    std::vector<LinkSpec> links;
    links.push_back({&s.k0, &s.k1, s.good_k1()});
    links.push_back({&s.k1, &s.t, s.good_t()});
    expect_refused("synthetic-incomplete-last-response",
                   s.run(one(chain_wire(s.k0.id, s.t.id, false, std::move(links)))), "completion flag");
  }
  if (selected("synthetic-truncated-at-key-block")) {
    std::vector<LinkSpec> links;
    links.push_back({&s.k0, &s.k1, s.good_k1()});
    expect_refused("synthetic-truncated-at-key-block", s.run(one(chain_wire(s.k0.id, s.k1.id, true, std::move(links)))),
                   "does not end at the exact target block");
  }
  // Control 6: an unauthenticated replacement set, self-signed, with the rest
  // of the chain consistent with it. The governing set for each link comes
  // from the already authenticated source, so neither variant can succeed.
  auto replacement = [&](const BlockFixture& key, const BlockFixture& target,
                         const td::Ref<block::ValidatorSet>& claimed, const td::Ref<vm::Cell>& session_config) {
    auto session_key = session_for(s.global_id, session_config, claimed, key);
    auto session_target = session_for(s.global_id, s.config_x, s.set_x, target);
    std::vector<LinkSpec> links;
    links.push_back({&s.k0, &key, sign(s.x, claimed, key, session_key, 2001)->tl_lite()});
    links.push_back({&key, &target, sign(s.x, s.set_x, target, session_target, 2002)->tl_lite()});
    auto request_text = "{\"mode\":\"historical\",\"target\":" + pv::block_id_json(target.id) + "}";
    auto request = must(pv::parse_request(request_text), "replacement request");
    pv::Material material;
    material.chain.push_back(chain_wire(s.k0.id, target.id, true, std::move(links)));
    return pv::verify(s.anchor, request, request_text, material, std::nullopt, at(kHistoricalNow));
  };
  if (selected("synthetic-unauthenticated-replacement")) {
    expect_refused("synthetic-unauthenticated-replacement", replacement(s.k1x, s.tx, s.set_x, s.config_x),
                   "stated in block header");
  }
  if (selected("synthetic-replacement-claims-current-set")) {
    expect_refused("synthetic-replacement-claims-current-set", replacement(s.k1y, s.ty, s.set_a, s.config_a),
                   "unknown validator_id");
  }
}

}  // namespace

void write_file(const std::string& path, td::Slice data) {
  must(td::write_file(path, data), "write " + path);
}

std::string live_request(const BlockIdExt& target) {
  return "{\"mode\":\"live\",\"max_age_seconds\":3600,\"target\":" + pv::block_id_json(target) + "}";
}

// Writes current-time synthetic material for the CLI live-state commit test:
// T (verified first, becomes the head), K1 (below the head) and T2 (another
// block at the head's height, authenticated by the same incoming set).
int write_live_fixture(const std::string& directory) {
  block_time_base = static_cast<td::uint32>(std::time(nullptr)) - 20;
  Synthetic s;
  auto t2 =
      make_block(s.global_id, 3, s.k1.id, s.set_b->get_catchain_seqno(), s.set_b->get_validator_set_hash(), 2, {}, 1);
  auto session_t2 = session_for(s.global_id, s.config_b, s.set_b, t2);
  for (const auto* name : {"material-t", "material-k1", "material-t2"}) {
    must(td::mkdir(directory + "/" + name), "mkdir");
  }
  write_file(directory + "/anchor.json", pv::render_anchor(s.anchor));
  write_file(directory + "/request-t.json", live_request(s.t.id));
  write_file(directory + "/material-t/chain-0000.tl", s.chain(s.good_k1(), s.good_t()));
  write_file(directory + "/request-k1.json", live_request(s.k1.id));
  write_file(directory + "/request-t2.json", live_request(t2.id));
  std::vector<LinkSpec> links;
  links.push_back({&s.k1, &t2, sign(s.b, s.set_b, t2, session_t2, 2003)->tl_lite()});
  write_file(directory + "/material-t2/chain-0000.tl", chain_wire(s.k1.id, t2.id, true, std::move(links)));
  std::printf("PROOF_VERIFY_LIVE_FIXTURE head=%u conflict_root=%s\n", s.t.id.seqno(), t2.id.root_hash.to_hex().c_str());
  return 0;
}

int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(FATAL));
  if (argc == 3 && std::string(argv[1]) == "--write-live-fixture") {
    return write_live_fixture(argv[2]);
  }
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--case" && i + 1 < argc) {
      only_case = argv[++i];
    } else {
      data_dir = arg;
    }
  }
  if (data_dir.empty()) {
    die("usage: test-proof-verify DATA_DIR [--case NAME]");
  }
  auto real = load_real();
  Synthetic synthetic;
  synthetic_cases(synthetic, real.anchor);
  real_cases(real, synthetic.anchor, synthetic.chain(synthetic.good_k1(), synthetic.good_t()));
  std::printf("PROOF_VERIFY_SUMMARY passed=%d failed=%d\n", passes, failures);
  if (passes == 0) {
    std::fprintf(stderr, "PROOF_VERIFY_TEST_SETUP_FAILURE: no case ran\n");
    return 2;
  }
  return failures == 0 ? 0 : 1;
}
