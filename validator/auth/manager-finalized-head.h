#pragma once
#include <map>
#include <memory>
#include <optional>

#include "native-finality.h"

namespace tos::auth {
// Joins two facts the manager learns on different asynchronous paths:
//
//   * the node's native finality verifier accepted a signature set for a block;
//   * that exact block was applied and its original bytes produced this state.
//
// Neither half is a finalized head. Only an exact BlockIdExt present in both
// maps is published to NativeFinalizedHeadEstablisher. Before any signed block
// exists, observe() exposes only the configured zero state.
class ManagerFinalizedHeadSource final : public NativeFinalizedHeadSource {
 public:
  static Result<std::unique_ptr<ManagerFinalizedHeadSource>> create(
      ChainContext chain, tos::BlockIdExt zero_block,
      td::Ref<vm::Cell> zero_state);

  Result<bool> note_verified(NativeFinalityVerification);
  Result<bool> note_applied(tos::BlockIdExt, Bytes original_block,
                            td::Ref<vm::Cell> resulting_state);

  Result<NativeHeadObservation> observe() const override;
  Result<NativeFinalityVerification> verify_signatures(
      const tos::BlockIdExt&) const override;

  const std::optional<tos::BlockIdExt>& latest_complete() const {
    return latest_complete_;
  }

 private:
  struct Applied {
    Bytes block;
    td::Ref<vm::Cell> state;
  };

  ManagerFinalizedHeadSource(ChainContext chain, tos::BlockIdExt zero_block,
                             td::Ref<vm::Cell> zero_state)
      : chain_(std::move(chain)),
        genesis_{std::move(zero_block), std::move(zero_state)} {
  }

  Result<bool> promote(const tos::BlockIdExt&);
  void prune();

  ChainContext chain_;
  NativeGenesisHeadCandidate genesis_;
  std::map<tos::BlockIdExt, NativeFinalityVerification> verified_;
  std::map<tos::BlockIdExt, Applied> applied_;
  std::optional<tos::BlockIdExt> latest_complete_;
};
}  // namespace tos::auth
