#pragma once
#include "native-committee.h"
#include "native-history.h"
#include "native-transaction.h"
namespace tos::auth {
// Immutable authority inputs for one masterchain successor. Construction binds
// the real config account's code/data/checkpoint to the authenticated parent.
class NativeConfigContext {
  ChainContext chain_;
  Anchor head_;
  Hash address_{};
  td::Ref<vm::Cell> code_, data_, library_, config_;
  NativeRegistry parent_;
  NativeCommittee committee_;
  NativeFinalizedHistory history_;
  NativeConfigContext(ChainContext chain, Anchor head, Hash address, td::Ref<vm::Cell> code, td::Ref<vm::Cell> data,
                      td::Ref<vm::Cell> library, td::Ref<vm::Cell> config, NativeRegistry parent,
                      NativeCommittee committee, NativeFinalizedHistory history);

 public:
  // A cached value is a previously validated native registry. Its complete
  // checkpoint must equal the checkpoint actually owned by this parent account.
  static Result<NativeConfigContext> open(td::Ref<vm::Cell> masterchain_state, const Anchor&, const ChainContext&,
                                          const NativeRegistry* cached = nullptr, StateReadBudget = {});
  Result<bool> binds(std::int32_t workchain, const Hash& address, td::Ref<vm::Cell> code, td::Ref<vm::Cell> data,
                     td::Ref<vm::Cell> library) const;
  const ChainContext& chain() const {
    return chain_;
  }
  const Anchor& head() const {
    return head_;
  }
  const Hash& address() const {
    return address_;
  }
  const NativeRegistry& parent() const {
    return parent_;
  }
  const NativeCommittee& committee() const {
    return committee_;
  }
  const NativeFinalizedHistory& history() const {
    return history_;
  }
  td::Ref<vm::Cell> config() const {
    return config_;
  }
  td::Ref<vm::Cell> data() const {
    return data_;
  }
};
}  // namespace tos::auth
