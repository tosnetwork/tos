#pragma once

#include <filesystem>
#include <utility>

#include "validator/auth/native-session-continuity.h"

#include "native-history-fixture.h"

namespace p0_session_continuity_fixture {
using namespace tos::auth;
using namespace p0_owner_fixture;

inline ChainContext read_chain(const std::filesystem::path& folder) {
  auto bytes = read(folder / "0.chain");
  Reader reader(bytes);
  ChainContext chain;
  reader.integer(chain.network);
  reader.hash(chain.genesis_root);
  reader.hash(chain.genesis_file);
  reader.hash(chain.chain_domain);
  check(reader.ok() && reader.remaining() == 0, "continuity-chain");
  return chain;
}

inline NativeSessionIdInput identity_input(std::uint64_t marker = 730) {
  return {h(marker), tos::masterchainId, tos::shardIdAll,
          17u, 41u, NativeSessionIdForm::group_new};
}

struct HistoryFixture {
  td::Ref<vm::Cell> head_state;
  td::Ref<vm::Cell> birth_state;
  td::Ref<vm::Cell> predecessor_state;
  Anchor head;
  Anchor birth;
  Anchor predecessor;
  ChainContext chain;
  Bytes birth_block;
  Bytes predecessor_block;
  NativeSessionIdInput supplied_identity = identity_input();

  Result<Bytes> block(const tos::BlockIdExt& id,
                      std::size_t maximum) const {
    const Anchor* expected = nullptr;
    const Bytes* raw = nullptr;
    if (id.seqno() == birth.seqno_) {
      expected = &birth;
      raw = &birth_block;
    } else if (id.seqno() == predecessor.seqno_) {
      expected = &predecessor;
      raw = &predecessor_block;
    } else {
      return Error{"continuity-block-request"};
    }
    if (id.root_hash.as_slice() !=
            td::Slice(expected->root_.data(), expected->root_.size()) ||
        id.file_hash.as_slice() !=
            td::Slice(expected->file_.data(), expected->file_.size()) ||
        raw->size() > maximum)
      return Error{"continuity-block-request"};
    return *raw;
  }

  Result<td::Ref<vm::Cell>> state(const Anchor& anchor) const {
    if (anchor == birth)
      return birth_state;
    if (anchor == predecessor)
      return predecessor_state;
    return Error{"continuity-state-request"};
  }

  Result<NativeSessionIdInput> identity(
      const Anchor& anchor, td::Ref<vm::Cell> state,
      tos::ShardIdFull target) const {
    if (state.is_null() || hash(state) != anchor.state_)
      return Error{"continuity-identity-state"};
    if (target.workchain != supplied_identity.workchain ||
        target.shard != supplied_identity.shard)
      return Error{"continuity-identity-target"};
    return supplied_identity;
  }

  NativeBlockReader blocks() const {
    return [this](const tos::BlockIdExt& id,
                  std::size_t maximum) -> Result<Bytes> {
      return block(id, maximum);
    };
  }

  NativeSessionStateReader states() const {
    return [this](const Anchor& anchor)
        -> Result<td::Ref<vm::Cell>> {
      return state(anchor);
    };
  }

  NativeSessionIdentityInputReader identities() const {
    return [this](const Anchor& anchor, td::Ref<vm::Cell> state,
                  tos::ShardIdFull target)
        -> Result<NativeSessionIdInput> {
      return identity(anchor, std::move(state), target);
    };
  }
};

inline HistoryFixture make_history(
    const std::filesystem::path& owner_inputs,
    const std::filesystem::path& committee_fixtures,
    NativeSessionIdInput input = identity_input()) {
  auto active = cell(read(committee_fixtures / "0.boc"));
  auto chain = read_chain(committee_fixtures);
  auto zero_state = history_state(active, 0, {});
  Anchor zero{0, hash(zero_state), file_hash(boc(zero_state)),
              hash(zero_state)};
  chain.genesis_root = zero.root_;
  chain.genesis_file = zero.file_;
  Entry zero_entry{0, 0, zero.root_, zero.file_};

  auto birth_state = history_state(active, 99, {zero_entry});
  auto predecessor_state =
      capabilities(history_state(active, 98, {zero_entry}), 16, 0);

  auto owner = fixture(owner_inputs);
  owner.chain.network = chain.network;
  auto transaction = cell(read(owner_inputs / "accept.boc"));

  auto birth_cell = block_for(transaction, birth_state, owner);
  auto birth_bytes = boc(birth_cell);
  Anchor birth{99, hash(birth_cell), file_hash(birth_bytes),
               hash(birth_state)};

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
       Entry{99, 99, birth.root_, birth.file_}});
  Anchor head{100, h(800), h(801), hash(head_state)};

  HistoryFixture result{
      head_state, birth_state, predecessor_state,
      head, birth, predecessor, chain,
      std::move(birth_bytes), std::move(predecessor_bytes)};
  result.supplied_identity = input;
  return result;
}

inline Result<std::shared_ptr<const NativeSessionCommitteeContext>>
make_context(const HistoryFixture& fixture,
             const NativeSessionIdInput& input) {
  auto birth = NativeSessionBirth::resolve(
      fixture.head_state, fixture.head, fixture.chain, input,
      fixture.blocks(), fixture.states(), fixture.identities());
  if (!birth.ok())
    return birth.error();
  return admit_native_session_committee(
      {}, birth.value(), fixture.chain);
}

}  // namespace p0_session_continuity_fixture
