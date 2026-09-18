#include "manager-finality-receipt.h"

namespace tos::auth {
Result<NativeFinalityVerification> verify_manager_finality_receipt(
    const tos::BlockIdExt& block,
    const td::Ref<block::BlockSignatureSet>& signatures,
    const td::Ref<block::ValidatorSet>& next,
    const td::Ref<block::ValidatorSet>& current) {
  if (signatures.is_null() || !signatures->is_final())
    return Error{"manager-finality-not-final"};

  auto verify = [&](const td::Ref<block::ValidatorSet>& set)
      -> std::optional<NativeFinalityVerification> {
    if (set.is_null())
      return std::nullopt;
    auto checked = signatures->check_signatures(set, block);
    if (checked.is_error())
      return std::nullopt;
    return NativeFinalityVerification{
        block,
        NativeSignatureSetKind::final,
        set->get_catchain_seqno(),
        set->get_validator_set_hash(),
        checked.ok(),
        set->get_total_weight()};
  };

  if (auto value = verify(next))
    return *value;
  if (auto value = verify(current))
    return *value;
  return Error{"manager-finality-signatures"};
}
}  // namespace tos::auth
