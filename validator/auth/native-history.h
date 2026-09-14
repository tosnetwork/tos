#pragma once
#include <cstdint>
#include <memory>
#include <span>

#include "tos/tos-types.h"

#include "native-apply.h"
namespace block {
class ConfigInfo;
}
namespace tos::auth {
// The source reads the exact original native block BOC for this authenticated ID.
// It must honor the size bound before allocating a complete response.
using NativeBlockReader = std::function<Result<Bytes>(const tos::BlockIdExt&, std::size_t)>;
struct HistoryReadBudget {
  std::size_t blocks = 129, bytes = 268435456;
};
// Parse one original masterchain block BOC into the exact anchor it commits.
// This authenticates structure/binding only; it does not establish finality.
Result<Anchor> native_masterchain_block_anchor(
    std::span<const std::uint8_t> raw, std::int32_t expected_network);
class NativeFinalizedHistory final : public FinalizedAnchorSource {
  std::unique_ptr<block::ConfigInfo> config_;
  Anchor head_;
  ChainContext chain_;
  NativeBlockReader read_;
  mutable HistoryReadBudget budget_;
  mutable std::map<std::uint32_t, Anchor> cache_;
  NativeFinalizedHistory();

 public:
  ~NativeFinalizedHistory();
  NativeFinalizedHistory(NativeFinalizedHistory&&) noexcept;
  NativeFinalizedHistory& operator=(NativeFinalizedHistory&&) noexcept;
  // The caller establishes head finality independently. The state must match
  // that entire anchor and the native genesis entry must match the chain context.
  static Result<NativeFinalizedHistory> open(td::Ref<vm::Cell> masterchain_state, const Anchor& head,
                                             const ChainContext&, NativeBlockReader, HistoryReadBudget = {});
  Result<Anchor> finalized_anchor(std::uint32_t coordinate) const override;
  // Fixed-surface witness, authenticated by this state's native history index.
  // Never consults the archive reader, cache, or mutable read budget.
  Result<Anchor> authenticate_header(std::uint32_t coordinate, td::Ref<vm::Cell> proof) const;
};
Result<td::Ref<vm::Cell>> native_header_proof(td::Ref<vm::Cell> block);
}  // namespace tos::auth
