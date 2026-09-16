#pragma once

#include <filesystem>
#include <fstream>
#include <iterator>
#include <utility>

#include "validator/auth/native-node-history.h"

#include "native-history-fixture.h"

namespace node_history_fixture {
using namespace tos::auth;
using namespace owner_fixture;

inline Bytes read_bytes(const std::filesystem::path& path) {
  std::ifstream file(path, std::ios::binary);
  check(file.good(), "node-history-input");
  return Bytes(std::istreambuf_iterator<char>(file), {});
}

inline ChainContext read_chain(const std::filesystem::path& folder) {
  auto raw = read_bytes(folder / "0.chain");
  Reader reader(raw);
  ChainContext chain;
  reader.integer(chain.network);
  reader.hash(chain.genesis_root);
  reader.hash(chain.genesis_file);
  reader.hash(chain.chain_domain);
  check(reader.ok() && reader.remaining() == 0, "node-history-chain");
  return chain;
}

inline NativeSessionIdInput identity_input() {
  return {h(730), tos::masterchainId, tos::shardIdAll,
          17u, 41u, NativeSessionIdForm::group_new};
}

struct Fixture {
  td::Ref<vm::Cell> head_state;
  td::Ref<vm::Cell> old_state;
  td::Ref<vm::Cell> predecessor_state;
  td::Ref<vm::Cell> missing_state;
  Anchor head;
  Anchor old;
  Anchor predecessor;
  Anchor missing;
  ChainContext chain;
  Bytes old_block;
  Bytes predecessor_block;
  NativeSessionIdInput identity;
  Duty duty;
  Certificate certificate;
  Hash duty_id;
  Hash certificate_id;
  Bytes duty_raw;
  Bytes certificate_raw;

  bool state_outage = false;
  bool substitute_state = false;
  bool block_outage = false;
  bool identity_outage = false;
  bool archive_outage = false;

  mutable unsigned block_reads = 0;
  mutable unsigned state_reads = 0;
  mutable unsigned identity_reads = 0;
  mutable unsigned duty_reads = 0;
  mutable unsigned certificate_reads = 0;

  Result<Bytes> read_block(const tos::BlockIdExt& id,
                           std::size_t maximum) const {
    ++block_reads;
    if (block_outage)
      return Error{"archive-offline"};
    const Anchor* expected = nullptr;
    const Bytes* raw = nullptr;
    if (id.seqno() == old.seqno_) {
      expected = &old;
      raw = &old_block;
    } else if (id.seqno() == predecessor.seqno_) {
      expected = &predecessor;
      raw = &predecessor_block;
    } else {
      return Error{"archive-missing"};
    }
    if (id.root_hash.as_slice() !=
            td::Slice(expected->root_.data(), expected->root_.size()) ||
        id.file_hash.as_slice() !=
            td::Slice(expected->file_.data(), expected->file_.size()) ||
        raw->size() > maximum)
      return Error{"archive-request"};
    return *raw;
  }

  Result<td::Ref<vm::Cell>> read_state(const Anchor& anchor) const {
    ++state_reads;
    if (state_outage)
      return Error{"storage-unavailable"};
    if (substitute_state && anchor.seqno_ == head.seqno_)
      return old_state;
    if (anchor.seqno_ == head.seqno_)
      return head_state;
    if (anchor.seqno_ == old.seqno_)
      return old_state;
    if (anchor.seqno_ == predecessor.seqno_)
      return predecessor_state;
    if (anchor.seqno_ == missing.seqno_)
      return head_state;  // Deliberate local-latest substitution probe.
    return Error{"state-missing"};
  }

  Result<NativeSessionIdInput> read_identity(
      const Anchor&, td::Ref<vm::Cell>,
      tos::ShardIdFull target) const {
    ++identity_reads;
    if (identity_outage)
      return Error{"storage-unavailable"};
    if (target.workchain != identity.workchain ||
        target.shard != identity.shard)
      return Error{"identity-missing"};
    return identity;
  }

  Result<Bytes> read_duty(const Anchor& anchor, const Hash& id,
                          std::size_t maximum) const {
    ++duty_reads;
    if (archive_outage)
      return Error{"archive-offline"};
    if (anchor != head || id != duty_id)
      return Error{"history-unavailable"};
    if (duty_raw.size() > maximum)
      return Error{"archive-bound"};
    return duty_raw;
  }

  Result<Bytes> read_certificate(const Anchor& anchor, const Hash& id,
                                 std::size_t maximum) const {
    ++certificate_reads;
    if (archive_outage)
      return Error{"archive-offline"};
    if (anchor != head || id != certificate_id)
      return Error{"history-unavailable"};
    if (certificate_raw.size() > maximum)
      return Error{"archive-bound"};
    return certificate_raw;
  }

  NativeNodeHistoryReaders readers() {
    return {
        [this](const tos::BlockIdExt& id,
               std::size_t maximum) -> Result<Bytes> {
          return read_block(id, maximum);
        },
        [this](const Anchor& anchor) -> Result<td::Ref<vm::Cell>> {
          return read_state(anchor);
        },
        [this](const Anchor& anchor, td::Ref<vm::Cell> state,
               tos::ShardIdFull target) -> Result<NativeSessionIdInput> {
          return read_identity(anchor, std::move(state), target);
        },
        [this](const Anchor& anchor, const Hash& id,
               std::size_t maximum) -> Result<Bytes> {
          return read_duty(anchor, id, maximum);
        },
        [this](const Anchor& anchor, const Hash& id,
               std::size_t maximum) -> Result<Bytes> {
          return read_certificate(anchor, id, maximum);
        }};
  }
};

inline Fixture make_fixture(
    const std::filesystem::path& owner_inputs,
    const std::filesystem::path& committee_fixtures) {
  auto active = cell(read_bytes(committee_fixtures / "0.boc"));
  auto chain = read_chain(committee_fixtures);
  auto zero_state = history_state(active, 0, {});
  Anchor zero{0, hash(zero_state), file_hash(boc(zero_state)),
              hash(zero_state)};
  chain.genesis_root = zero.root_;
  chain.genesis_file = zero.file_;
  Entry zero_entry{0, 0, zero.root_, zero.file_};

  auto old_state = history_state(active, 99, {zero_entry});
  auto predecessor_state =
      capabilities(history_state(active, 98, {zero_entry}), 16, 0);
  auto missing_state = history_state(active, 97, {zero_entry});

  auto owner = fixture(owner_inputs);
  owner.chain.network = chain.network;
  auto transaction = cell(read_bytes(owner_inputs / "accept.boc"));

  auto old_cell = block_for(transaction, old_state, owner);
  auto old_bytes = boc(old_cell);
  Anchor old{99, hash(old_cell), file_hash(old_bytes), hash(old_state)};

  auto predecessor_cell =
      alter_block(block_for(transaction, predecessor_state, owner), 2);
  auto predecessor_bytes = boc(predecessor_cell);
  Anchor predecessor{
      98, hash(predecessor_cell), file_hash(predecessor_bytes),
      hash(predecessor_state)};

  auto head_state = history_state(
      active, 100,
      {zero_entry,
       Entry{98, 98, predecessor.root_, predecessor.file_},
       Entry{99, 99, old.root_, old.file_}});
  Anchor head{100, h(800), h(801), hash(head_state)};
  Anchor missing{97, h(970), h(971), hash(head_state)};

  auto input = identity_input();
  auto epoch = derive_native_session_epoch(head_state, head, chain, input);
  check(epoch.ok() && epoch.value().has_value(), "node-history-epoch");
  auto native = NativeCommittee::derive(
      head_state, head, chain,
      {input.workchain, input.shard}, epoch.value()->catchain);
  check(native.ok(), "node-history-committee");
  const auto& snapshot = native.value().snapshot();

  auto session = session_id(
      chain, snapshot,
      {input.native_options_hash, input.maximal_vertical_seqno,
       input.last_key_block_seqno});
  check(session.ok(), "node-history-session");
  Bytes payload{0x05, 0xe1, 0xa7, 0x40, 0x3f, 0xcd, 0x91, 0xb6,
                7, 0, 0, 0};
  auto candidate = h(6100);
  payload.insert(payload.end(), candidate.begin(), candidate.end());
  auto duty = make_duty(chain, snapshot, session.value(), 3, 7, payload);
  check(duty.ok(), "node-history-duty");

  Certificate certificate{duty.value(), payload, {}};
  const auto& members = snapshot.committee().members_;
  check(members.size() >= 2, "node-history-members");
  for (std::size_t i = 0; i < 2; ++i) {
    check(members[i].keys_.size() >= 3, "node-history-member-keys");
    auto ref = key_reference(members[i].keys_[2]);
    check(ref.ok(), "node-history-keyref");
    certificate.records_.push_back(
        {members[i].identity_,
         {{ref.value().suite_, ref.value().parameters_,
           ref.value().epoch_, ref.value().key_id_, {}}}});
  }

  auto duty_raw = encode_native_duty_history_record(
      {duty.value(), payload});
  auto certificate_raw = encode(certificate);
  check(duty_raw.ok() && certificate_raw.ok(), "node-history-archive-encode");
  auto duty_id = object_id("duty", duty.value());
  auto certificate_id = object_id("certificate", certificate);
  check(duty_id.ok() && certificate_id.ok(), "node-history-archive-id");

  return Fixture{
      head_state,
      old_state,
      predecessor_state,
      missing_state,
      head,
      old,
      predecessor,
      missing,
      chain,
      std::move(old_bytes),
      std::move(predecessor_bytes),
      input,
      duty.value(),
      certificate,
      duty_id.value(),
      certificate_id.value(),
      std::move(duty_raw.value()),
      std::move(certificate_raw.value())};
}

inline tos::BlockIdExt block_id(const Anchor& anchor) {
  return {{tos::masterchainId, tos::shardIdAll, anchor.seqno_},
          td::Bits256(td::ConstBitPtr(anchor.root_.data())),
          td::Bits256(td::ConstBitPtr(anchor.file_.data()))};
}

inline bool same_identity_input(const NativeSessionIdInput& left,
                                const NativeSessionIdInput& right) {
  return left.native_options_hash == right.native_options_hash &&
         left.workchain == right.workchain &&
         left.shard == right.shard &&
         left.maximal_vertical_seqno == right.maximal_vertical_seqno &&
         left.last_key_block_seqno == right.last_key_block_seqno &&
         left.form == right.form;
}

}  // namespace node_history_fixture
