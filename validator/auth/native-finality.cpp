#include "native-finality.h"

#include <algorithm>

#include "tos/quorum.h"

namespace tos::auth {
namespace {

Hash cell_hash(const td::Ref<vm::Cell>& cell) {
  Hash result{};
  if (cell.is_null())
    return result;
  // get_hash() returns by value, so a slice of it must not outlive the full
  // expression that produced it. Hold the hash itself, not a view into a
  // temporary that has already been destroyed.
  const auto hash = cell->get_hash();
  const auto raw = hash.as_slice();
  if (raw.size() != result.size())
    return {};
  std::copy(raw.ubegin(), raw.uend(), result.begin());
  return result;
}

tos::BlockIdExt block_id(const Anchor& anchor) {
  return {
      {tos::masterchainId, tos::shardIdAll, anchor.seqno_},
      td::Bits256(td::ConstBitPtr(anchor.root_.data())),
      td::Bits256(td::ConstBitPtr(anchor.file_.data()))};
}

}  // namespace

Result<std::unique_ptr<NativeFinalizedHeadEstablisher>>
NativeFinalizedHeadEstablisher::create(
    ChainContext chain, NativeFinalizedHeadSource& source) {
  if (chain.genesis_root == Hash{} ||
      chain.genesis_file == Hash{} ||
      chain.chain_domain == Hash{})
    return Error{"chain-context"};

  return std::unique_ptr<NativeFinalizedHeadEstablisher>(
      new NativeFinalizedHeadEstablisher(
          std::move(chain), source));
}

Result<EstablishedNativeHead>
NativeFinalizedHeadEstablisher::establish() {
  auto observed = source_.observe();
  if (!observed.ok())
    return observed.error();

  if (observed.value().peer_claim)
    return Error{"finalized-head-peer-claim"};

  Anchor anchor_value{};
  td::Ref<vm::Cell> resulting_state;

  if (observed.value().finality_candidate) {
    const auto& candidate = *observed.value().finality_candidate;
    auto anchor =
        native_masterchain_block_anchor(
            candidate.block, chain_.network);
    if (!anchor.ok())
      return anchor.error();

    const auto resulting_hash =
        cell_hash(candidate.resulting_state);
    if (candidate.resulting_state.is_null() ||
        candidate.resulting_state->get_level() != 0 ||
        resulting_hash != anchor.value().state_)
      return Error{"finalized-head-state-binding"};

    const auto id = block_id(anchor.value());
    auto verified = source_.verify_signatures(id);
    if (!verified.ok())
      return verified.error();

    if (verified.value().block != id)
      return Error{"finalized-head-signature-binding"};

    if (verified.value().kind !=
        NativeSignatureSetKind::final)
      return Error{"finalized-head-approval-only"};

    if (verified.value().total_weight == 0 ||
        verified.value().signed_weight >
            verified.value().total_weight ||
        !tos::has_quorum(
            verified.value().signed_weight,
            verified.value().total_weight))
      return Error{"finalized-head-quorum"};

    anchor_value = anchor.value();
    resulting_state = candidate.resulting_state;
  } else if (observed.value().configured_genesis) {
    const auto& genesis = *observed.value().configured_genesis;
    const auto root = td::Bits256(td::ConstBitPtr(chain_.genesis_root.data()));
    const auto file = td::Bits256(td::ConstBitPtr(chain_.genesis_file.data()));
    if (!genesis.block.is_masterchain_ext() ||
        genesis.block.id.seqno != 0 ||
        genesis.block.root_hash != root ||
        genesis.block.file_hash != file)
      return Error{"finalized-head-genesis-binding"};

    const auto state_hash = cell_hash(genesis.resulting_state);
    if (genesis.resulting_state.is_null() ||
        genesis.resulting_state->get_level() != 0 ||
        state_hash != chain_.genesis_root)
      return Error{"finalized-head-genesis-state"};

    anchor_value =
        Anchor{0, chain_.genesis_root, chain_.genesis_file,
               chain_.genesis_root};
    resulting_state = genesis.resulting_state;
  } else {
    return Error{"finalized-head-unavailable"};
  }

  if (current_) {
    if (anchor_value.seqno_ < current_->seqno_)
      return Error{"finalized-head-regression"};
    if (anchor_value.seqno_ == current_->seqno_ &&
        anchor_value != *current_)
      return Error{"finalized-head-conflict"};
  }

  current_ = anchor_value;
  return EstablishedNativeHead(
      anchor_value, std::move(resulting_state), chain_);
}

}  // namespace tos::auth
