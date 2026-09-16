#pragma once
#include "block/mc-config.h"

#include "native-committee.h"
#include "native-history.h"
#include "native-transaction.h"
namespace tos::auth {
// The configuration account a masterchain state declares, bound to that state:
// the address in configuration parameter zero must equal the one the state's
// own configuration header carries. Two callers need this fact -- the authority
// inputs below, and deciding whether a message is addressed to that account --
// and a second reading of it would be a second source that nothing compares.
Result<Hash> declared_configuration_account(const block::Config& config, td::Ref<vm::Cell> masterchain_state);

// What a configuration account's persistent data holds, read once.
//
// Two callers need these: opening the parent context, and deciding whether a
// committed transaction installed the prefix its host authorized. A second
// reading of the same cell is the shape this design has already paid for --
// two descriptions of one fact, each correct in its own suite, disagreeing only
// where they meet.
struct ConfigurationAccountData {
  td::Ref<vm::Cell> configuration;  // the parameter dictionary, the leading ref
  td::Ref<vm::Cell> checkpoint;     // the registry checkpoint, the trailing ref
};
Result<ConfigurationAccountData> read_configuration_account(td::Ref<vm::Cell> data);

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
