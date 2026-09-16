#pragma once
// A parent state that carries its own history, and the witnesses an owner
// approval can name.
//
// Admission authenticates the witness a message carries against the parent
// state's native history index. Both halves have to be real for that to mean
// anything: a hand-filled anchor authenticates against nothing, and a state
// with no index refuses before the witness is ever read. Composed here out of
// the two fixtures that already build those halves -- the configuration
// context and the history index -- so nothing in this file is a second encoder
// for a state, a block, or an anchor.
//
// The anchor of each block comes from the same function production uses to
// read one, and the index entry is filled from that anchor. A fixture that
// wrote those hashes itself would be agreeing with itself.
#include <filesystem>

#include "native-config-context-fixture.h"
#include "native-history-fixture.h"

namespace owner_history_fixture {
using namespace tos::auth;
using namespace auth_fixture;
using owner_fixture::block_for;
using owner_fixture::boc;
using owner_fixture::cell;
using owner_fixture::fixture;
using owner_fixture::hash;
using owner_fixture::read;

// A finalized masterchain block, the anchor it commits, and the fixed-surface
// witness that proves that anchor against an index holding it.
struct WitnessedBlock {
  std::uint32_t at{};
  td::Ref<vm::Cell> block;
  Anchor anchor;
  td::Ref<vm::Cell> witness;
};

struct OwnerHistoryFixture {
  td::Ref<vm::Cell> root;  // the parent state, carrying the index of both blocks
  Anchor head;
  ChainContext chain;
  Hash address;
  WitnessedBlock owner, other;
};

// block_for produces a masterchain block at a fixed coordinate. Authentication
// binds a block to the coordinate it is indexed under, so the coordinate is set
// here rather than chosen to match what the builder happens to write.
inline td::Ref<vm::Cell> at_coordinate(td::Ref<vm::Cell> block, std::uint32_t at) {
  block::gen::Block::Record record;
  block::gen::BlockInfo::Record info;
  check(tlb::unpack_cell(block, record) && tlb::unpack_cell(record.info, info), "owner-history-block");
  info.seq_no = at;
  check(tlb::pack_cell(record.info, info) && tlb::pack_cell(block, record), "owner-history-block-pack");
  return block;
}

// `owner_at` and the coordinate above it are finalized and indexed; the state
// returned is the one after both. Two blocks rather than one, because a witness
// that authenticates for the wrong coordinate is only distinguishable from a
// correct one when a second real coordinate exists to name.
inline OwnerHistoryFixture make_with_owner_history(td::Ref<vm::Cell> base,
                                                   const std::filesystem::path& owner_inputs,
                                                   std::uint32_t owner_at = 7) {
  check(owner_at >= 1, "owner-history-coordinate");
  auto context = config_context_fixture::make(std::move(base));

  // Opening a history refuses unless the chain context names the entry the
  // index itself holds at coordinate zero, so the genesis state is built first
  // and the context corrected to it.
  auto genesis_state = history_state(context.root, 0, {});
  Entry genesis{0, 0, hash(genesis_state), file_hash(boc(genesis_state))};

  auto transaction = cell(read(owner_inputs / "accept.boc"));
  auto owner = fixture(owner_inputs);
  owner.chain.network = context.chain.network;

  auto historical = [&](std::uint32_t at) {
    auto state = history_state(context.root, at, {genesis});
    auto previous = history_state(context.root, at - 1, {genesis});
    auto block = at_coordinate(block_for(transaction, state, owner), at);
    block = replace_ref(block, 2, vm::CellBuilder::create_merkle_update(previous, state));
    WitnessedBlock witnessed;
    witnessed.at = at;
    witnessed.block = block;
    witnessed.anchor = value(native_masterchain_block_anchor(boc(block), context.chain.network),
                             "owner-history-anchor");
    witnessed.witness = value(native_header_proof(block), "owner-history-witness");
    return witnessed;
  };

  OwnerHistoryFixture result;
  result.address = context.address;
  result.owner = historical(owner_at);
  result.other = historical(owner_at + 1);

  auto head_state = history_state(
      context.root, owner_at + 2,
      {genesis,
       Entry{result.owner.at, result.owner.at, result.owner.anchor.root_, result.owner.anchor.file_},
       Entry{result.other.at, result.other.at, result.other.anchor.root_, result.other.anchor.file_}});
  result.root = head_state;
  result.head = {owner_at + 2, hash(head_state), file_hash(boc(head_state)), hash(head_state)};
  result.chain = context.chain;
  result.chain.genesis_root = genesis.root;
  result.chain.genesis_file = genesis.file;
  return result;
}
}  // namespace owner_history_fixture
